package com.security.pipeline.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Gate-2 "understanding code structure" tool (design doc: tree-sitter). Uses the tree-sitter CLI to
 * parse the changed source files and produce a lightweight structural summary (how many parsed
 * cleanly, how many had syntax errors) that accompanies the AI review. It requires the tree-sitter
 * CLI and language grammars to be configured on the host; when they are not, it degrades to
 * UNAVAILABLE and the pipeline continues without it.
 */
@Service
public class TreeSitterService {

    @Value("${secgate.tree-sitter-binary:tree-sitter}")
    private String binary;

    @Value("${secgate.tree-sitter.max-files:15}")
    private int maxFiles;

    public ToolReport summarize(Path repoDir, List<String> changedFiles) {
        if (repoDir == null || changedFiles == null || changedFiles.isEmpty()) {
            return ToolReport.skipped("no changed files to parse");
        }

        // Availability probe — cheap and avoids per-file spawn when the CLI is missing.
        if (!isAvailable(repoDir)) {
            return ToolReport.unavailable("tree-sitter CLI not available");
        }

        int parsed = 0;
        int errored = 0;
        int attempted = 0;
        for (String file : changedFiles) {
            if (attempted >= maxFiles) {
                break;
            }
            if (!isParseableSource(file)) {
                continue;
            }
            attempted++;
            Integer exit = runParse(repoDir, file);
            if (exit == null) {
                // Grammar not configured for this language — treat as unavailable overall.
                return ToolReport.unavailable("tree-sitter grammars not configured");
            }
            if (exit == 0) {
                parsed++;
            } else {
                errored++;
            }
        }

        if (attempted == 0) {
            return ToolReport.skipped("no parseable source files in the change");
        }
        String summary = "Parsed " + parsed + "/" + attempted + " changed file(s)"
                + (errored > 0 ? ", " + errored + " with syntax errors" : "");
        return new ToolReport(ToolReport.PASS, summary, List.of());
    }

    private boolean isAvailable(Path repoDir) {
        Integer exit = runCommand(repoDir, List.of(binary, "--version"));
        return exit != null && exit == 0;
    }

    /** Returns the process exit code, or {@code null} if the binary could not be executed. */
    private Integer runParse(Path repoDir, String file) {
        return runCommand(repoDir, List.of(binary, "parse", "--quiet", file));
    }

    private Integer runCommand(Path repoDir, List<String> command) {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(repoDir.toFile());
        pb.redirectErrorStream(true);
        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            return null;
        }
        try {
            // Drain output so the process is not blocked on a full pipe.
            process.getInputStream().readAllBytes();
            boolean completed = process.waitFor(30, TimeUnit.SECONDS);
            if (!completed) {
                process.destroyForcibly();
                return 1;
            }
            return process.exitValue();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return 1;
        } catch (IOException e) {
            return 1;
        }
    }

    private boolean isParseableSource(String file) {
        if (file == null) {
            return false;
        }
        String lower = file.toLowerCase();
        return lower.endsWith(".java") || lower.endsWith(".js") || lower.endsWith(".ts")
                || lower.endsWith(".py") || lower.endsWith(".go") || lower.endsWith(".rb")
                || lower.endsWith(".c") || lower.endsWith(".cpp") || lower.endsWith(".rs");
    }
}
