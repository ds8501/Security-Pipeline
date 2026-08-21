package com.security.pipeline.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.pipeline.ai.ClaudeClient;
import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

@Service
public class ProofService {
    private final ClaudeClient claudeClient;
    private final SandboxService sandboxService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${secgate.semgrep-binary:semgrep}")
    private String semgrepBinary;

    public ProofService(ClaudeClient claudeClient, SandboxService sandboxService) {
        this.claudeClient = claudeClient;
        this.sandboxService = sandboxService;
    }

    public void proveAll(Scan scan, List<Finding> findings, Path repoDir) {
        if (findings == null || findings.isEmpty() || repoDir == null) {
            return;
        }

        for (Finding finding : findings) {
            try {
                String ruleText = generateRule(finding);
                Path tempRule = Files.createTempFile("secgate-rule-", ".yaml");
                Files.writeString(tempRule, ruleText, StandardCharsets.UTF_8);

                ProcessBuilder processBuilder = new ProcessBuilder(
                        semgrepBinary,
                        "--config",
                        tempRule.toString(),
                        "--json",
                        "--quiet",
                        "."
                );
                processBuilder.directory(repoDir.toFile());
                processBuilder.redirectErrorStream(true);
                Process process = processBuilder.start();
                boolean complete = process.waitFor(45, java.util.concurrent.TimeUnit.SECONDS);
                String output = complete ? new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8) : "";
                if (!complete) {
                    process.destroyForcibly();
                    finding.setProofStatus("UNPROVEN");
                    finding.setProof(ruleText + "\n\nSemgrep timed out.");
                    continue;
                }

                JsonNode result = objectMapper.readTree(output.isBlank() ? "{\"results\":[]}" : output);
                JsonNode results = result.path("results");
                boolean confirmed = results.isArray() && !results.isEmpty();
                finding.setProofStatus(confirmed ? "CONFIRMED" : "UNPROVEN");
                finding.setProof(ruleText + "\n\nSemgrep result: " + (confirmed ? "matched " + results.size() + " finding(s)" : "no matches found"));
            } catch (Exception e) {
                finding.setProofStatus("UNPROVEN");
                finding.setProof("Unable to verify with Semgrep. " + e.getMessage());
            }

            // Second proof path (design doc Layer 7): if the Semgrep rule did not confirm the issue,
            // try to prove it by running an LLM-generated check inside a network-disabled Docker
            // sandbox. Opt-in and a no-op when Docker is unavailable, so it never downgrades a
            // Semgrep-confirmed finding.
            if (!"CONFIRMED".equalsIgnoreCase(finding.getProofStatus())
                    && sandboxService != null && sandboxService.isEnabled()) {
                try {
                    SandboxService.SandboxResult sandbox = sandboxService.proveByTest(finding, repoDir);
                    if (sandbox.confirmed()) {
                        finding.setProofStatus("CONFIRMED");
                        finding.setProof(finding.getProof() + "\n\nSandbox test proof (network-disabled Docker):\n" + sandbox.detail());
                    } else if ("UNPROVEN".equalsIgnoreCase(finding.getProofStatus())) {
                        finding.setProof(finding.getProof() + "\n\nSandbox test proof: " + sandbox.status() + " — " + sandbox.detail());
                    }
                } catch (Exception ignored) {
                    // Sandbox failures never affect the Semgrep-derived status.
                }
            }
        }
    }

    private String generateRule(Finding finding) {
        String system = "Return only a single YAML Semgrep rule. It must be valid YAML and detect the described pattern precisely. No markdown fences.";
        String user = "Generate one Semgrep rule for this issue. Use only YAML. Issue title: " + finding.getTitle()
                + "\nSeverity: " + finding.getSeverity()
                + "\nFile: " + finding.getFile()
                + "\nDescription: " + finding.getDescription()
                + "\nFix: " + finding.getFix();

        String content = claudeClient.complete(system, user, 1200);
        if (content == null || content.isBlank()) {
            return fallbackRule(finding);
        }

        String cleaned = content.trim();
        if (cleaned.startsWith("```")) {
            cleaned = cleaned.replaceFirst("^```(?:yaml|yml)?\\s*", "")
                    .replaceFirst("\\s*```$", "")
                    .trim();
        }
        if (cleaned.contains("rules:")) {
            return cleaned;
        }
        return fallbackRule(finding);
    }

    private String fallbackRule(Finding finding) {
        String ruleId = "secgate-" + Math.abs((finding.getTitle() + finding.getFile()).hashCode());
        return "rules:\n"
                + "  - id: " + ruleId + "\n"
                + "    patterns:\n"
                + "      - pattern: " + "" + "\n"
                + "    message: " + finding.getTitle() + "\n"
                + "    severity: " + normalizeSeverity(finding.getSeverity()) + "\n"
                + "    languages: [python, java, javascript, typescript]\n"
                + "    metadata:\n"
                + "      category: security\n"
                + "      cwe: \"" + safe(finding.getCwe()) + "\"\n"
                + "    paths:\n"
                + "      include:\n"
                + "        - '**/*.py'\n"
                + "        - '**/*.java'\n"
                + "        - '**/*.js'\n"
                + "        - '**/*.ts'\n";
    }

    private String normalizeSeverity(String severity) {
        if (severity == null) {
            return "WARNING";
        }
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> "ERROR";
            case "HIGH" -> "ERROR";
            case "MEDIUM" -> "WARNING";
            default -> "INFO";
        };
    }

    private String safe(String value) {
        return value == null ? "CWE-693" : value.replace("\n", " ");
    }
}
