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
 * Gate-1 secret detection via Gitleaks.
 */
@Component
public class GitleaksTool extends AbstractProcessTool {

    @Value("${secgate.gitleaks-binary:gitleaks}")
    private String binary;

    @Override
    public String id() {
        return "gitleaks";
    }

    @Override
    public String label() {
        return "Gitleaks (secrets)";
    }

    @Override
    public int order() {
        return 20;
    }

    @Override
    public Gate1Result scan(Path repoDir) {
        Path report;
        try {
            report = Files.createTempFile("secgate-gitleaks-", ".json");
        } catch (Exception e) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Could not create report file", List.of());
        }

        ProcessOutcome outcome = run(repoDir, List.of(binary, "detect", "--source", ".",
                "--report-format", "json", "--report-path", report.toString(),
                "--exit-code", "0", "--no-banner"), 120);
        if (!outcome.started()) {
            return Gate1Result.unavailable(id(), "Gitleaks binary not found");
        }
        if (outcome.timedOut()) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Gitleaks timed out", List.of());
        }

        try {
            String json = Files.exists(report) ? Files.readString(report) : "[]";
            JsonNode root = objectMapper.readTree(json.isBlank() ? "[]" : json);
            List<Finding> findings = new ArrayList<>();
            if (root.isArray()) {
                for (JsonNode leak : root) {
                    String rule = leak.path("RuleID").asText("secret");
                    String file = leak.path("File").asText("unknown");
                    int line = leak.path("StartLine").asInt(1);
                    String desc = leak.path("Description").asText("Potential secret committed to the repository");
                    findings.add(finding("Secret leak: " + rule, "CRITICAL", file, line, desc,
                            "Remove the secret, rotate it, and load it from a secret manager instead.",
                            "CWE-798", "A07:2021", "Gitleaks matched rule " + rule + " at " + file + ":" + line));
                }
            }
            String summary = findings.isEmpty() ? "No secrets detected" : findings.size() + " potential secret(s)";
            return new Gate1Result(id(), findings.isEmpty() ? Gate1Result.PASS : Gate1Result.FAIL, summary, findings);
        } catch (Exception e) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Could not parse Gitleaks output: " + e.getMessage(), List.of());
        } finally {
            try {
                Files.deleteIfExists(report);
            } catch (Exception ignored) {
            }
        }
    }
}
