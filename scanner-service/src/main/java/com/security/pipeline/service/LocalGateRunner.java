package com.security.pipeline.service;

import com.security.pipeline.entity.Gate1Check;
import com.security.pipeline.entity.Gate1Run;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

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

    private record Tool(String name, List<String> command, boolean atRepoRoot, int timeoutSeconds) {
    }

    // Heavy tools (mvn test + Trivy) are off by default so Gate 1 stays fast and responsive on
    // small hosts (e.g. Render free tier). Set secgate.gate1.heavy-tools=true on a bigger instance
    // to run the full suite.
    @Value("${secgate.gate1.heavy-tools:false}")
    private boolean heavyTools;

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
            // Fast scanners run always; heavy tools (mvn test, Trivy) only when explicitly enabled.
            List<Tool> tools = new ArrayList<>();
            // Unit tests & coverage always run in Gate 1. generous timeout: the first run
            // downloads Maven and all dependencies.
            tools.add(new Tool("Unit tests & coverage", mavenCommand(pom), false, 900));
            tools.add(new Tool("Code sanity & crypto (Semgrep)",
                    // --max-memory + single job keep Semgrep within a 512MB host's budget
                    List.of("semgrep", "scan", "--error", "--quiet", "--jobs", "1", "--max-memory", "300",
                            "--config", "p/security-audit", "."), true, 300));
            tools.add(new Tool("Secret leak (Gitleaks)",
                    List.of("gitleaks", "detect", "--source", ".", "--no-banner", "--redact"), true, 300));
            tools.add(new Tool("Vulnerable dependencies (osv-scanner)",
                    List.of("osv-scanner", "scan", "-r", "."), true, 300));
            if (heavyTools) {
                tools.add(new Tool("Infra & container config (Trivy)",
                        List.of("trivy", "config", "--quiet", "."), true, 300));
            }
            tools.add(new Tool("SBOM (Syft)",
                    List.of("syft", "scan", "dir:.", "-o", "cyclonedx-json"), true, 300));

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
                    ExecResult res = exec(tool.command(), workDir, tool.timeoutSeconds());
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
        // Cap Maven's own JVM so the mvn test step fits alongside the service on a 512MB host.
        pb.environment().putIfAbsent("MAVEN_OPTS", "-Xmx256m");
        Process p = pb.start();               // throws IOException if the binary is missing
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        boolean done = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!done) {
            p.destroyForcibly();
            return new ExecResult(124, out + "\n(timed out)");
        }
        return new ExecResult(p.exitValue(), out);
    }

    /**
     * Prefers the Maven wrapper checked in next to the pom (works on hosts without a system
     * mvn — the wrapper bootstraps its own Maven) and falls back to the system install.
     */
    private List<String> mavenCommand(Path pom) {
        if (pom == null) {
            return null;
        }
        Path parent = pom.getParent();
        Path wrapper = parent != null ? parent.resolve("mvnw") : null;
        String mvn;
        if (wrapper != null && Files.isRegularFile(wrapper)) {
            // git preserves the exec bit, but be defensive about checkouts that don't
            if (!Files.isExecutable(wrapper)) {
                wrapper.toFile().setExecutable(true);
            }
            mvn = wrapper.toAbsolutePath().toString();
        } else {
            mvn = "mvn";
        }
        // "nice" lowers the build's CPU priority so the web thread stays responsive on a single
        // core; -DforkCount=0 runs tests in the Maven JVM (no extra forked JVM) to fit small hosts.
        return List.of("nice", "-n", "15", mvn, "-q", "-B", "-DforkCount=0", "-f", pom.toString(), "test");
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
