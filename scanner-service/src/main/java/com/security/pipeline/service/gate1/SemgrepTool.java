package com.security.pipeline.service.gate1;

import com.fasterxml.jackson.databind.JsonNode;
import com.security.pipeline.entity.Finding;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Gate-1 SAST via Semgrep's {@code p/security-audit} ruleset.
 */
@Component
public class SemgrepTool extends AbstractProcessTool {

    @Value("${secgate.semgrep-binary:semgrep}")
    private String binary;

    @Value("${secgate.gate1.semgrep-config:p/security-audit}")
    private String config;

    @Override
    public String id() {
        return "semgrep";
    }

    @Override
    public String label() {
        return "Semgrep (SAST)";
    }

    @Override
    public int order() {
        return 10;
    }

    @Override
    public Gate1Result scan(Path repoDir) {
        ProcessOutcome outcome = run(repoDir,
                List.of(binary, "--config", config, "--json", "--quiet", "--timeout", "0", "."), 180);
        if (!outcome.started()) {
            return Gate1Result.unavailable(id(), "Semgrep binary not found");
        }
        if (outcome.timedOut()) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Semgrep timed out", List.of());
        }

        try {
            JsonNode root = objectMapper.readTree(outcome.output().isBlank() ? "{}" : outcome.output());
            JsonNode results = root.path("results");
            List<Finding> findings = new ArrayList<>();
            if (results.isArray()) {
                for (JsonNode r : results) {
                    JsonNode extra = r.path("extra");
                    String severity = extra.path("severity").asText("WARNING");
                    String message = extra.path("message").asText("Semgrep rule matched");
                    String checkId = r.path("check_id").asText("semgrep-rule");
                    String file = r.path("path").asText("unknown");
                    int line = r.path("start").path("line").asInt(1);
                    String cwe = firstText(extra.path("metadata").path("cwe"));
                    String owasp = firstText(extra.path("metadata").path("owasp"));
                    findings.add(finding(checkId, severity, file, line, message,
                            "Apply the remediation suggested by the Semgrep rule.",
                            cwe, owasp, "Semgrep rule " + checkId + " matched at " + file + ":" + line));
                }
            }
            String summary = findings.isEmpty() ? "No SAST issues found" : findings.size() + " SAST issue(s) found";
            return new Gate1Result(id(), findings.isEmpty() ? Gate1Result.PASS : Gate1Result.FAIL, summary, findings);
        } catch (Exception e) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Could not parse Semgrep output: " + e.getMessage(), List.of());
        }
    }

    private String firstText(JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return null;
        }
        if (node.isArray()) {
            return node.isEmpty() ? null : node.get(0).asText(null);
        }
        return node.asText(null);
    }
}
