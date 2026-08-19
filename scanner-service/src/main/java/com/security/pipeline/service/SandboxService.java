package com.security.pipeline.service;

import com.security.pipeline.ai.ClaudeClient;
import com.security.pipeline.entity.Finding;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Gate-2 "run generated tests safely" tool (design doc Layer 7, second proof path).
 *
 * <p>For a finding, the LLM writes a small self-checking proof script; the script runs inside a
 * <strong>network-disabled, resource-capped, ephemeral Docker container</strong> with the repo
 * mounted read-only. Running model-generated code is exactly why the sandbox exists, so this is
 * opt-in ({@code secgate.sandbox.enabled}) and degrades to a no-op when Docker is absent.
 *
 * <p>Contract with the model: the script prints {@code PROOF_CONFIRMED} and exits 0 <em>only</em>
 * if the described vulnerability is actually present; otherwise it exits non-zero. Any Docker or
 * execution error is therefore treated as "not proven", never a false confirmation.
 */
@Service
public class SandboxService {

    private static final String CONFIRM_MARKER = "PROOF_CONFIRMED";

    private final ClaudeClient claudeClient;

    @Value("${secgate.sandbox.enabled:false}")
    private boolean enabled;

    @Value("${secgate.docker-binary:docker}")
    private String dockerBinary;

    @Value("${secgate.sandbox.image:python:3.12-alpine}")
    private String image;

    @Value("${secgate.sandbox.timeout-seconds:90}")
    private int timeoutSeconds;

    public SandboxService(ClaudeClient claudeClient) {
        this.claudeClient = claudeClient;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** Outcome of a sandboxed proof attempt. */
    public record SandboxResult(boolean confirmed, String status, String detail) {
        static SandboxResult skipped(String why) {
            return new SandboxResult(false, "SKIPPED", why);
        }

        static SandboxResult unavailable(String why) {
            return new SandboxResult(false, "UNAVAILABLE", why);
        }
    }

    /**
     * Attempts to prove {@code finding} by running an LLM-generated check script in the sandbox.
     * Returns a non-confirming result (never throws) if disabled, if Docker is missing, or if the
     * script does not demonstrate the issue.
     */
    public SandboxResult proveByTest(Finding finding, Path repoDir) {
        if (!enabled) {
            return SandboxResult.skipped("sandbox disabled");
        }
        if (repoDir == null) {
            return SandboxResult.skipped("no repository directory");
        }
        if (claudeClient == null || !claudeClient.isConfigured()) {
            return SandboxResult.skipped("LLM not configured");
        }

        String script = generateCheckScript(finding);
        if (script == null || script.isBlank()) {
            return SandboxResult.skipped("no proof script generated");
        }

        Path proofDir = null;
        try {
            proofDir = Files.createTempDirectory("secgate-proof-");
            Path scriptPath = proofDir.resolve("check.sh");
            Files.writeString(scriptPath, script, StandardCharsets.UTF_8);

            // Network-disabled, resource-capped, ephemeral container. Repo and script are mounted
            // read-only; there is no writable path outside the container's own layer.
            List<String> command = List.of(
                    dockerBinary, "run", "--rm",
                    "--network", "none",
                    "--memory", "256m",
                    "--cpus", "1",
                    "--pids-limit", "128",
                    "-v", repoDir.toAbsolutePath() + ":/work:ro",
                    "-v", proofDir.toAbsolutePath() + ":/proof:ro",
                    "-w", "/work",
                    image,
                    "sh", "/proof/check.sh"
            );

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);

            Process process;
            try {
                process = pb.start();
            } catch (IOException e) {
                return SandboxResult.unavailable("Docker not available: " + e.getMessage());
            }

            boolean completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!completed) {
                process.destroyForcibly();
                return new SandboxResult(false, "TIMEOUT", "Sandbox proof timed out after " + timeoutSeconds + "s");
            }

            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            boolean confirmed = process.exitValue() == 0 && output.contains(CONFIRM_MARKER);
            String detail = truncate(output, 1500);
            return new SandboxResult(confirmed, confirmed ? "CONFIRMED" : "UNPROVEN",
                    "Exit " + process.exitValue() + "\n" + detail);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return SandboxResult.skipped("interrupted");
        } catch (Exception e) {
            return SandboxResult.unavailable("Sandbox error: " + e.getMessage());
        } finally {
            cleanup(proofDir);
        }
    }

    private String generateCheckScript(Finding finding) {
        String system = "You write a single POSIX shell script that verifies whether a specific vulnerability is "
                + "present in a repository mounted read-only at /work. The script MUST have NO network access, "
                + "make NO changes outside its own process, and finish quickly. It MUST print the exact token "
                + CONFIRM_MARKER + " and exit 0 ONLY if it concretely demonstrates the described vulnerability "
                + "(e.g. the vulnerable code path or pattern is actually present at the given location); "
                + "otherwise it must exit 1 and NOT print that token. Return only the script, no markdown fences.";
        String user = "Repository is at /work (read-only). Write the verification script for this finding.\n"
                + "Title: " + finding.getTitle() + "\n"
                + "Severity: " + finding.getSeverity() + "\n"
                + "File: " + finding.getFile() + (finding.getLine() == null ? "" : (":" + finding.getLine())) + "\n"
                + "Description: " + finding.getDescription() + "\n"
                + "Suggested fix: " + finding.getFix();

        String content = claudeClient.complete(system, user, 900);
        if (content == null) {
            return null;
        }
        String cleaned = content.trim();
        if (cleaned.startsWith("```")) {
            cleaned = cleaned.replaceFirst("^```(?:sh|bash)?\\s*", "").replaceFirst("\\s*```$", "").trim();
        }
        return cleaned.isBlank() ? null : cleaned;
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.length() <= max ? trimmed : trimmed.substring(0, max) + "…";
    }

    private void cleanup(Path dir) {
        if (dir == null) {
            return;
        }
        try {
            Files.walk(dir)
                    .sorted((a, b) -> b.getNameCount() - a.getNameCount())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (IOException ignored) {
                        }
                    });
        } catch (IOException ignored) {
        }
    }
}
