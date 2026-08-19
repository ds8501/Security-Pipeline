package com.security.pipeline.service;

import com.security.pipeline.entity.Gate1Check;
import com.security.pipeline.entity.Gate1Run;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Runs the Gate-1 checks locally as subprocesses against a freshly cloned copy of the repo.
 * This is the fallback path when GitHub isn't configured — the same capability, self-contained.
 * Any tool that isn't installed is reported as "skipped" rather than failing the whole run.
 */
@Component
public class LocalGateRunner {

    private record Tool(String name, List<String> command, boolean atRepoRoot) {
    }

    public void run(Gate1Run gate) {
        Path root = null;
        try {
            gate.setStatus("running");
            gate.getLog().add("Cloning " + gate.getRepoUrl() + " (" + gate.getRef() + ")");
            root = Files.createTempDirectory("gate1-");
            Path repoDir = root.resolve("repo");
            int cloneCode = exec(List.of("git", "clone", "--quiet", "--depth", "1",
                    "--branch", gate.getRef(), gate.getRepoUrl(), repoDir.toString()), root, 120).exitCode();
            if (cloneCode != 0) {
                // fall back to default branch clone
                exec(List.of("git", "clone", "--quiet", "--depth", "1", gate.getRepoUrl(), repoDir.toString()), root, 120);
            }

            Path pom = findPom(repoDir);
            List<Tool> tools = List.of(
                    new Tool("Unit tests & coverage",
                            pom == null ? null : List.of("mvn", "-q", "-B", "-f", pom.toString(), "test"), false),
                    new Tool("Code sanity & crypto (Semgrep)",
                            List.of("semgrep", "scan", "--error", "--quiet", "--config", "p/security-audit", "."), true),
                    new Tool("Secret leak (Gitleaks)",
                            List.of("gitleaks", "detect", "--source", ".", "--no-banner", "--redact"), true),
                    new Tool("Vulnerable dependencies (osv-scanner)",
                            List.of("osv-scanner", "scan", "-r", "."), true),
                    new Tool("Infra & container config (Trivy)",
                            List.of("trivy", "config", "--quiet", "."), true),
                    new Tool("SBOM (Syft)",
                            List.of("syft", "scan", "dir:.", "-o", "cyclonedx-json"), true)
            );

            boolean blocked = false;
            for (Tool tool : tools) {
                Gate1Check check = new Gate1Check(tool.name());
                gate.getChecks().add(check);
                if (tool.command() == null) {
                    check.setStatus("skipped");
                    check.setConclusion("skipped");
                    check.setDetails("No Maven project found to test.");
                    continue;
                }
                check.setStatus("running");
                Path workDir = tool.atRepoRoot() ? repoDir : repoDir;
                try {
                    ExecResult res = exec(tool.command(), workDir, 300);
                    check.setStatus("completed");
                    if (res.exitCode() == 0) {
                        check.setConclusion("success");
                        check.setDetails("Passed.");
                    } else {
                        check.setConclusion("failure");
                        check.setDetails(tail(res.output(), 500));
                        blocked = true;
                    }
                } catch (IOException toolMissing) {
                    check.setStatus("skipped");
                    check.setConclusion("skipped");
                    check.setDetails("Tool not installed on the host: " + tool.command().get(0));
                }
                gate.getLog().add(tool.name() + " -> " + check.getConclusion());
            }

            gate.setStatus("completed");
            gate.setConclusion(blocked ? "BLOCKED" : "PASS");
            gate.setSummary(blocked ? "One or more checks failed." : "All runnable checks passed.");
        } catch (Exception e) {
            gate.setStatus("error");
            gate.setConclusion("ERROR");
            gate.setSummary("Local gate run failed: " + e.getMessage());
            gate.getLog().add("ERROR: " + e.getMessage());
        } finally {
            cleanup(root);
        }
    }

    private record ExecResult(int exitCode, String output) {
    }

    private ExecResult exec(List<String> command, Path workDir, int timeoutSeconds) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(workDir.toFile());
        pb.redirectErrorStream(true);
        Process p = pb.start();               // throws IOException if the binary is missing
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        boolean done = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!done) {
            p.destroyForcibly();
            return new ExecResult(124, out + "\n(timed out)");
        }
        return new ExecResult(p.exitValue(), out);
    }

    private Path findPom(Path repoDir) {
        try (Stream<Path> walk = Files.walk(repoDir, 4)) {
            return walk.filter(p -> p.getFileName().toString().equals("pom.xml"))
                    .filter(p -> !p.toString().contains("/target/"))
                    .findFirst().orElse(null);
        } catch (IOException e) {
            return null;
        }
    }

    private String tail(String s, int max) {
        if (s == null) {
            return "";
        }
        s = s.strip();
        return s.length() <= max ? s : "…" + s.substring(s.length() - max);
    }

    private void cleanup(Path path) {
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
}
