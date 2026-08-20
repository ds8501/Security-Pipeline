package com.security.pipeline.service;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

@Service
public class GitService {
    private static final Duration COMMAND_TIMEOUT = Duration.ofSeconds(45);

    public DiffContext fetchDiff(String repoUrl, String branch, String baseBranch) {
        Path tempRoot = null;
        Path repoDir = null;
        try {
            tempRoot = Files.createTempDirectory("secgate-root-");
            repoDir = tempRoot.resolve("repo");
            runCommand(List.of("git", "clone", "--quiet", "--filter=blob:none", repoUrl, repoDir.toString()), tempRoot, COMMAND_TIMEOUT);

            String safeBase = baseBranch == null ? "main" : baseBranch.trim();
            String safeBranch = branch == null ? "main" : branch.trim();

            runCommand(List.of("git", "-C", repoDir.toString(), "fetch", "--quiet", "--no-tags", "origin",
                    safeBase + ":refs/remotes/origin/" + safeBase, safeBranch + ":refs/remotes/origin/" + safeBranch), repoDir, COMMAND_TIMEOUT);

            // Check out the branch entered in the UI (fetched from git) into the working tree, so the
            // tools that read the working tree — ripgrep, tree-sitter, and the red-team's
            // .secgate/services.yaml inventory — analyze THAT branch, not the clone's default branch
            // or the scanner-service's own running branch.
            runCommand(List.of("git", "-C", repoDir.toString(), "checkout", "--quiet", "--force",
                    "-B", safeBranch, "origin/" + safeBranch), repoDir, COMMAND_TIMEOUT);

            String rawDiff = runCommand(List.of("git", "-C", repoDir.toString(), "diff", "origin/" + safeBase + "...origin/" + safeBranch), repoDir, COMMAND_TIMEOUT);
            String nameOnly = runCommand(List.of("git", "-C", repoDir.toString(), "diff", "--name-only", "origin/" + safeBase + "...origin/" + safeBranch), repoDir, COMMAND_TIMEOUT);

            List<String> changedFiles = new ArrayList<>();
            for (String line : nameOnly.split("\\R")) {
                String normalized = line.trim();
                if (normalized.isBlank()) {
                    continue;
                }
                if (shouldSkipPath(normalized)) {
                    continue;
                }
                changedFiles.add(normalized);
            }

            if (changedFiles.size() > 25) {
                changedFiles = changedFiles.subList(0, 25);
            }

            Map<String, String> fileContents = new LinkedHashMap<>();
            for (String file : changedFiles) {
                String text = readChangedFile(repoDir, safeBranch, file);
                if (text == null || text.isBlank()) {
                    continue;
                }
                if (text.length() > 20000) {
                    text = text.substring(0, 20000);
                }
                fileContents.put(file, text);
            }

            return new DiffContext(repoDir, rawDiff, changedFiles, fileContents);
        } catch (Exception e) {
            if (repoDir != null) {
                cleanup(repoDir);
            }
            return new DiffContext(repoDir, "", List.of(), Map.of());
        }
    }

    public void cleanup(Path path) {
        if (path == null) {
            return;
        }

        try (Stream<Path> walk = Files.walk(path)) {
            walk.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                    .forEach(current -> {
                        try {
                            Files.deleteIfExists(current);
                        } catch (IOException ignored) {
                        }
                    });
        } catch (IOException ignored) {
        }
    }

    private String readChangedFile(Path repoDir, String branch, String file) {
        try {
            String content = runCommand(List.of("git", "-C", repoDir.toString(), "show", "origin/" + branch + ":" + file), repoDir, COMMAND_TIMEOUT);
            if (isBinary(content)) {
                return null;
            }
            return content;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean shouldSkipPath(String path) {
        String normalized = path.replace('\\', '/').toLowerCase(Locale.ROOT);
        if (normalized.isBlank() || normalized.startsWith("target/") || normalized.contains("/target/") || normalized.endsWith(".class")) {
            return true;
        }
        if (normalized.contains("package-lock.json") || normalized.contains("yarn.lock") || normalized.contains("pnpm-lock.yaml") || normalized.contains("pom.lock") || normalized.contains("lock") && normalized.endsWith(".lock")) {
            return true;
        }
        if (normalized.endsWith(".png") || normalized.endsWith(".jpg") || normalized.endsWith(".jpeg") || normalized.endsWith(".gif")
                || normalized.endsWith(".svg") || normalized.endsWith(".ico") || normalized.endsWith(".pdf") || normalized.endsWith(".zip")
                || normalized.endsWith(".bin") || normalized.endsWith(".jar") || normalized.endsWith(".war") || normalized.endsWith(".mp4")
                || normalized.endsWith(".mp3") || normalized.endsWith(".exe") || normalized.endsWith(".dll") || normalized.endsWith(".so")
                || normalized.endsWith(".dylib")) {
            return true;
        }
        return false;
    }

    private boolean isBinary(String content) {
        if (content == null || content.isBlank()) {
            return false;
        }
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 0 && bytes[0] == 0) {
            return true;
        }
        int suspicious = 0;
        for (byte current : bytes) {
            if (current == 0) {
                return true;
            }
            if (current < 9 || current == 127) {
                suspicious++;
            }
        }
        return suspicious > 0;
    }

    private String runCommand(List<String> command, Path workingDir, Duration timeout) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(workingDir.toFile());
        processBuilder.redirectErrorStream(true);

        Process process = processBuilder.start();
        boolean completed = process.waitFor(timeout.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
        if (!completed) {
            process.destroyForcibly();
            throw new IllegalStateException("Timed out while running: " + command);
        }

        return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
}
