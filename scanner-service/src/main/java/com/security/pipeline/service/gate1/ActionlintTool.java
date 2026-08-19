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
 * Gate-1 GitHub Actions workflow linting via actionlint. Lint issues are reported at LOW/MEDIUM so
 * they surface without hard-blocking the merge (only HIGH/CRITICAL block).
 */
@Component
public class ActionlintTool extends AbstractProcessTool {

    @Value("${secgate.actionlint-binary:actionlint}")
    private String binary;

    @Override
    public String id() {
        return "actionlint";
    }

    @Override
    public String label() {
        return "actionlint (workflows)";
    }

    @Override
    public int order() {
        return 60;
    }

    @Override
    public Gate1Result scan(Path repoDir) {
        // Nothing to lint if the repo has no workflows.
        if (!Files.isDirectory(repoDir.resolve(".github").resolve("workflows"))) {
            return Gate1Result.skipped(id(), "No .github/workflows directory");
        }

        ProcessOutcome outcome = run(repoDir, List.of(binary, "-format", "{{json .}}", "-no-color"), 120);
        if (!outcome.started()) {
            return Gate1Result.unavailable(id(), "actionlint binary not found");
        }
        if (outcome.timedOut()) {
            return new Gate1Result(id(), Gate1Result.FAIL, "actionlint timed out", List.of());
        }

        try {
            String out = outcome.output();
            int bracket = out.indexOf('[');
            if (bracket < 0) {
                return new Gate1Result(id(), Gate1Result.PASS, "No workflow lint issues", List.of());
            }
            JsonNode root = objectMapper.readTree(out.substring(bracket));
            List<Finding> findings = new ArrayList<>();
            if (root.isArray()) {
                for (JsonNode err : root) {
                    String file = err.path("filepath").asText(".github/workflows");
                    int line = err.path("line").asInt(1);
                    String message = err.path("message").asText("Workflow lint issue");
                    String kind = err.path("kind").asText("actionlint");
                    findings.add(finding("Workflow lint: " + kind, "LOW", file, line, message,
                            "Fix the workflow issue reported by actionlint.",
                            "CWE-1164", "A05:2021", "actionlint: " + message));
                }
            }
            String summary = findings.isEmpty() ? "No workflow lint issues" : findings.size() + " workflow lint issue(s)";
            return new Gate1Result(id(), findings.isEmpty() ? Gate1Result.PASS : Gate1Result.FAIL, summary, findings);
        } catch (Exception e) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Could not parse actionlint output: " + e.getMessage(), List.of());
        }
    }
}
