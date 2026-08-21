package com.security.pipeline.service.gate1;

import com.fasterxml.jackson.databind.JsonNode;
import com.security.pipeline.entity.Finding;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Gate-1 infrastructure / container / filesystem scanning via Trivy (vuln + misconfig + secret).
 */
@Component
public class TrivyTool extends AbstractProcessTool {

    @Value("${secgate.trivy-binary:trivy}")
    private String binary;

    @Override
    public String id() {
        return "trivy";
    }

    @Override
    public String label() {
        return "Trivy (infra/config)";
    }

    @Override
    public int order() {
        return 40;
    }

    @Override
    public Gate1Result scan(Path repoDir) {
        ProcessOutcome outcome = run(repoDir, List.of(binary, "fs", "--scanners", "vuln,misconfig,secret",
                "--format", "json", "--quiet", "."), 240);
        if (!outcome.started()) {
            return Gate1Result.unavailable(id(), "Trivy binary not found");
        }
        if (outcome.timedOut()) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Trivy timed out", List.of());
        }

        try {
            String out = outcome.output();
            int brace = out.indexOf('{');
            if (brace < 0) {
                return new Gate1Result(id(), Gate1Result.PASS, "No infra/config issues found", List.of());
            }
            JsonNode root = objectMapper.readTree(out.substring(brace));
            List<Finding> findings = new ArrayList<>();
            for (JsonNode result : root.path("Results")) {
                String target = result.path("Target").asText("config");
                // Vulnerabilities
                for (JsonNode v : result.path("Vulnerabilities")) {
                    String id = v.path("VulnerabilityID").asText("VULN");
                    String pkg = v.path("PkgName").asText("");
                    String sev = v.path("Severity").asText("MEDIUM");
                    String title = v.path("Title").asText(id + " in " + pkg);
                    findings.add(finding("Trivy: " + title, sev, target, 1,
                            v.path("Description").asText(""), "Upgrade the affected package.",
                            "CWE-1104", "A06:2021", "Trivy reported " + id + " in " + pkg));
                }
                // Misconfigurations (IaC / Dockerfile / k8s)
                for (JsonNode m : result.path("Misconfigurations")) {
                    String id = m.path("ID").asText("MISCONF");
                    String sev = m.path("Severity").asText("MEDIUM");
                    String title = m.path("Title").asText("Misconfiguration " + id);
                    int line = m.path("CauseMetadata").path("StartLine").asInt(1);
                    findings.add(finding("Trivy: " + title, sev, target, line,
                            m.path("Message").asText(m.path("Description").asText("")),
                            m.path("Resolution").asText("Fix the misconfiguration."),
                            "CWE-1032", "A05:2021", "Trivy misconfig " + id + " at " + target));
                }
                // Embedded secrets
                for (JsonNode s : result.path("Secrets")) {
                    String rule = s.path("RuleID").asText("secret");
                    int line = s.path("StartLine").asInt(1);
                    findings.add(finding("Trivy secret: " + rule, "CRITICAL", target, line,
                            s.path("Title").asText("Secret detected"),
                            "Remove and rotate the secret; load it from a secret manager.",
                            "CWE-798", "A07:2021", "Trivy matched secret rule " + rule));
                }
            }
            String summary = findings.isEmpty() ? "No infra/config issues found" : findings.size() + " infra/config finding(s)";
            return new Gate1Result(id(), findings.isEmpty() ? Gate1Result.PASS : Gate1Result.FAIL, summary, findings);
        } catch (Exception e) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Could not parse Trivy output: " + e.getMessage(), List.of());
        }
    }
}
