package com.security.pipeline.service.gate1;

import com.fasterxml.jackson.databind.JsonNode;
import com.security.pipeline.entity.Finding;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Gate-1 vulnerable-dependency scanning via osv-scanner.
 */
@Component
public class OsvScannerTool extends AbstractProcessTool {

    @Value("${secgate.osv-scanner-binary:osv-scanner}")
    private String binary;

    @Override
    public String id() {
        return "osv-scanner";
    }

    @Override
    public String label() {
        return "osv-scanner (dependencies)";
    }

    @Override
    public int order() {
        return 30;
    }

    @Override
    public Gate1Result scan(Path repoDir) {
        // osv-scanner exits non-zero when vulns are found; that's expected, not an error.
        ProcessOutcome outcome = run(repoDir, List.of(binary, "--format", "json", "-r", "."), 180);
        if (!outcome.started()) {
            return Gate1Result.unavailable(id(), "osv-scanner binary not found");
        }
        if (outcome.timedOut()) {
            return new Gate1Result(id(), Gate1Result.FAIL, "osv-scanner timed out", List.of());
        }

        try {
            String out = outcome.output();
            int brace = out.indexOf('{');
            if (brace < 0) {
                return new Gate1Result(id(), Gate1Result.PASS, "No vulnerable dependencies found", List.of());
            }
            JsonNode root = objectMapper.readTree(out.substring(brace));
            List<Finding> findings = new ArrayList<>();
            for (JsonNode result : root.path("results")) {
                String source = result.path("source").path("path").asText("dependencies");
                for (JsonNode pkg : result.path("packages")) {
                    String name = pkg.path("package").path("name").asText("dependency");
                    String version = pkg.path("package").path("version").asText("");
                    for (JsonNode vuln : pkg.path("vulnerabilities")) {
                        String vulnId = vuln.path("id").asText("OSV");
                        String severity = extractSeverity(vuln);
                        String summary = vuln.path("summary").asText(name + " " + version + " is vulnerable");
                        findings.add(finding(vulnId + ": " + name + " " + version, severity, source, 1, summary,
                                "Upgrade " + name + " to a fixed version.", "CWE-1104", "A06:2021",
                                "osv-scanner reported " + vulnId + " for " + name + " " + version));
                    }
                }
            }
            String summary = findings.isEmpty() ? "No vulnerable dependencies found" : findings.size() + " vulnerable dependency finding(s)";
            return new Gate1Result(id(), findings.isEmpty() ? Gate1Result.PASS : Gate1Result.FAIL, summary, findings);
        } catch (Exception e) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Could not parse osv-scanner output: " + e.getMessage(), List.of());
        }
    }

    private String extractSeverity(JsonNode vuln) {
        // Prefer the explicit database_specific severity when present, else fall back to HIGH.
        JsonNode dbSpecific = vuln.path("database_specific").path("severity");
        if (dbSpecific.isTextual()) {
            return dbSpecific.asText();
        }
        JsonNode sev = vuln.path("severity");
        if (sev.isArray() && !sev.isEmpty()) {
            return "HIGH";
        }
        return "HIGH";
    }
}
