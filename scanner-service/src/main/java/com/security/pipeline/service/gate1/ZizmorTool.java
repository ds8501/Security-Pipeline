package com.security.pipeline.service.gate1;

import com.fasterxml.jackson.databind.JsonNode;
import com.security.pipeline.entity.Finding;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Gate-1 CI/CD pipeline hardening via zizmor, which audits GitHub Actions workflows for security
 * weaknesses (injection, excessive permissions, unpinned actions, ...).
 */
@Component
public class ZizmorTool extends AbstractProcessTool {

    @Value("${secgate.zizmor-binary:zizmor}")
    private String binary;

    @Override
    public String id() {
        return "zizmor";
    }

    @Override
    public String label() {
        return "zizmor (pipeline hardening)";
    }

    @Override
    public int order() {
        return 70;
    }

    @Override
    public Gate1Result scan(Path repoDir) {
        Path workflows = repoDir.resolve(".github").resolve("workflows");
        if (!Files.isDirectory(workflows)) {
            return Gate1Result.skipped(id(), "No .github/workflows directory");
        }

        ProcessOutcome outcome = run(repoDir,
                List.of(binary, "--format", "json", "--no-progress", ".github/workflows"), 120);
        if (!outcome.started()) {
            return Gate1Result.unavailable(id(), "zizmor binary not found");
        }
        if (outcome.timedOut()) {
            return new Gate1Result(id(), Gate1Result.FAIL, "zizmor timed out", List.of());
        }

        try {
            String out = outcome.output();
            int bracket = out.indexOf('[');
            if (bracket < 0) {
                return new Gate1Result(id(), Gate1Result.PASS, "No pipeline hardening issues", List.of());
            }
            JsonNode root = objectMapper.readTree(out.substring(bracket));
            List<Finding> findings = new ArrayList<>();
            if (root.isArray()) {
                for (JsonNode item : root) {
                    String ruleId = item.path("ident").asText(item.path("desc").asText("zizmor"));
                    // zizmor severities are informational..high; cap at MEDIUM so lint never blocks.
                    String rawSeverity = item.path("determinations").path("severity").asText("MEDIUM");
                    String severity = capSeverity(normalizeSeverity(rawSeverity));
                    String desc = item.path("desc").asText("Pipeline hardening issue");

                    JsonNode locations = item.path("locations");
                    String file = ".github/workflows";
                    int line = 1;
                    if (locations.isArray() && !locations.isEmpty()) {
                        JsonNode symbolic = locations.get(0).path("symbolic");
                        file = symbolic.path("key").path("Local").path("given_path").asText(file);
                        line = locations.get(0).path("concrete").path("location").path("start_point").path("row").asInt(1);
                    }
                    findings.add(finding("Pipeline: " + ruleId, severity, file, line, desc,
                            "Harden the workflow per zizmor's guidance (pin actions, least-privilege permissions).",
                            "CWE-1357", "A05:2021", "zizmor: " + ruleId));
                }
            }
            String summary = findings.isEmpty() ? "No pipeline hardening issues" : findings.size() + " pipeline hardening issue(s)";
            return new Gate1Result(id(), findings.isEmpty() ? Gate1Result.PASS : Gate1Result.FAIL, summary, findings);
        } catch (Exception e) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Could not parse zizmor output: " + e.getMessage(), List.of());
        }
    }

    private String capSeverity(String severity) {
        return "CRITICAL".equals(severity) || "HIGH".equals(severity) ? "MEDIUM" : severity;
    }
}
