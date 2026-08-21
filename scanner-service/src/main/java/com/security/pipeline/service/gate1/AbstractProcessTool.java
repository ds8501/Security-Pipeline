package com.security.pipeline.service.gate1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.pipeline.entity.Finding;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Shared scaffolding for Gate-1 tools that shell out to an external binary: it runs the process
 * with a timeout, distinguishes "binary not installed" from a real failure, and offers helpers to
 * build findings with normalized severities. Findings from Gate-1 tools are deterministic scanner
 * output, so they are marked {@code CONFIRMED} — no LLM proof step is needed for them.
 */
public abstract class AbstractProcessTool implements Gate1Tool {

    protected final ObjectMapper objectMapper = new ObjectMapper();

    /** Result of running an external process. */
    protected record ProcessOutcome(boolean started, boolean timedOut, int exitCode, String output) {
        boolean ok() {
            return started && !timedOut;
        }
    }

    /**
     * Runs {@code command} in {@code workingDir}. Returns {@code started=false} if the binary is
     * missing (so the caller can report UNAVAILABLE) and {@code timedOut=true} if it overran.
     */
    protected ProcessOutcome run(Path workingDir, List<String> command, int timeoutSeconds) {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(workingDir.toFile());
        pb.redirectErrorStream(true);

        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            // Command not found / not executable on this host.
            return new ProcessOutcome(false, false, -1, e.getMessage());
        }

        try {
            boolean completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!completed) {
                process.destroyForcibly();
                return new ProcessOutcome(true, true, -1, "");
            }
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return new ProcessOutcome(true, false, process.exitValue(), output);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return new ProcessOutcome(true, true, -1, "");
        } catch (IOException e) {
            return new ProcessOutcome(true, false, -1, e.getMessage());
        }
    }

    /** Builds a Gate-1 finding tagged with this tool's origin and marked as confirmed. */
    protected Finding finding(String title, String severity, String file, int line,
                              String description, String fix, String cwe, String owasp, String proof) {
        Finding f = new Finding();
        f.setTitle(title == null || title.isBlank() ? label() + " finding" : title);
        f.setSeverity(normalizeSeverity(severity));
        f.setFile(file == null || file.isBlank() ? "unknown" : file);
        f.setLine(line <= 0 ? 1 : line);
        f.setDescription(description == null ? "" : description);
        f.setFix(fix == null || fix.isBlank() ? "Review and remediate per the tool's guidance." : fix);
        f.setCwe(cwe == null || cwe.isBlank() ? "CWE-1035" : cwe);
        f.setOwasp(owasp == null || owasp.isBlank() ? "A06:2021" : owasp);
        f.setLayer("Gate 1 · " + label());
        f.setProofStatus("CONFIRMED");
        f.setProof(proof == null ? "" : proof);
        return f;
    }

    /** Maps assorted tool severity vocabularies onto CRITICAL/HIGH/MEDIUM/LOW. */
    protected String normalizeSeverity(String raw) {
        if (raw == null) {
            return "MEDIUM";
        }
        return switch (raw.trim().toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> "CRITICAL";
            case "ERROR", "BLOCKER", "HIGH" -> "HIGH";
            case "MEDIUM", "MODERATE", "WARNING" -> "MEDIUM";
            case "LOW", "INFO", "INFORMATIONAL", "NOTE", "UNKNOWN" -> "LOW";
            default -> "MEDIUM";
        };
    }

    protected String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        String trimmed = value.trim();
        return trimmed.length() <= max ? trimmed : trimmed.substring(0, max) + "…";
    }
}
