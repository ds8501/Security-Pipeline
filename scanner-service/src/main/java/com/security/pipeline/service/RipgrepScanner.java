package com.security.pipeline.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.pipeline.entity.Finding;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Gate-2 "code searching" tool (design doc: ripgrep). Fast pattern sweep for security hotspots the
 * AI reviewer should look at — hardcoded secrets, command execution, weak hashing, disabled TLS
 * verification, unsafe deserialization. Matches are recorded as LOW/MEDIUM findings so they surface
 * without hard-blocking the merge, and degrade to UNAVAILABLE when {@code rg} is not installed.
 */
@Service
public class RipgrepScanner {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${secgate.ripgrep-binary:rg}")
    private String binary;

    // Ordered so the first matching pattern labels the finding.
    private static final List<Hotspot> HOTSPOTS = List.of(
            new Hotspot("(?i)(password|passwd|pwd)\\s*[:=]\\s*[\"'][^\"']+[\"']", "Hardcoded password", "MEDIUM", "CWE-798"),
            new Hotspot("(?i)(api[_-]?key|secret|token)\\s*[:=]\\s*[\"'][^\"']+[\"']", "Hardcoded secret/API key", "MEDIUM", "CWE-798"),
            new Hotspot("Runtime\\.getRuntime\\(\\)\\.exec|ProcessBuilder\\(|child_process|os\\.system\\(|subprocess\\.", "Command execution", "MEDIUM", "CWE-78"),
            new Hotspot("\\beval\\s*\\(|\\bexec\\s*\\(", "Dynamic code execution", "MEDIUM", "CWE-95"),
            new Hotspot("pickle\\.loads|yaml\\.load\\s*\\(|readObject\\s*\\(", "Unsafe deserialization", "MEDIUM", "CWE-502"),
            new Hotspot("(?i)verify\\s*=\\s*False|InsecureSkipVerify|TrustAllCerts|ALLOW_ALL_HOSTNAME", "Disabled TLS verification", "MEDIUM", "CWE-295"),
            // NOTE: ripgrep's default (Rust regex) engine has no look-around, so avoid it here —
            // a single unsupported pattern makes rg error out and drop ALL matches.
            new Hotspot("(?i)\\bMD5\\b|\\bSHA-?1\\b|\\bDES\\b|\\bRC4\\b|\\bECB\\b", "Weak cryptographic primitive", "LOW", "CWE-327")
    );

    private record Hotspot(String regex, String title, String severity, String cwe) {
    }

    public ToolReport scan(Path repoDir) {
        if (repoDir == null) {
            return ToolReport.skipped("no repository directory");
        }

        List<String> command = new ArrayList<>(List.of(binary, "--json", "--no-heading", "--line-number"));
        for (Hotspot h : HOTSPOTS) {
            command.add("-e");
            command.add(h.regex());
        }
        command.add(".");

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(repoDir.toFile());
        pb.redirectErrorStream(false);

        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            return ToolReport.unavailable("ripgrep (rg) not found");
        }

        try {
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            boolean completed = process.waitFor(90, TimeUnit.SECONDS);
            if (!completed) {
                process.destroyForcibly();
                return new ToolReport(ToolReport.FAIL, "ripgrep timed out", List.of());
            }

            List<Finding> findings = parse(output);
            // Hotspots are advisory (LOW/MEDIUM) — reported as PASS so they inform without alarming;
            // they never set a blocking verdict on their own.
            String summary = findings.isEmpty() ? "No security hotspots found" : findings.size() + " security hotspot(s) flagged for review";
            return new ToolReport(ToolReport.PASS, summary, findings);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return ToolReport.skipped("interrupted");
        } catch (Exception e) {
            return new ToolReport(ToolReport.FAIL, "ripgrep error: " + e.getMessage(), List.of());
        }
    }

    private List<Finding> parse(String jsonlOutput) {
        // Deduplicate to one finding per file+line.
        Map<String, Finding> byLocation = new LinkedHashMap<>();
        for (String line : jsonlOutput.split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            try {
                JsonNode node = objectMapper.readTree(line);
                if (!"match".equals(node.path("type").asText())) {
                    continue;
                }
                JsonNode data = node.path("data");
                String file = data.path("path").path("text").asText("unknown");
                int lineNo = data.path("line_number").asInt(1);
                String text = data.path("lines").path("text").asText("").strip();
                Hotspot hotspot = classify(text);

                String key = file + ":" + lineNo;
                byLocation.computeIfAbsent(key, k -> {
                    Finding f = new Finding();
                    f.setTitle("Hotspot: " + hotspot.title());
                    f.setSeverity(hotspot.severity());
                    f.setFile(file);
                    f.setLine(lineNo);
                    f.setDescription("ripgrep flagged a security-sensitive pattern here for reviewer attention.");
                    f.setFix("Confirm whether this usage is safe; prefer parameterized/least-privilege alternatives.");
                    f.setCwe(hotspot.cwe());
                    f.setOwasp("A06:2021");
                    f.setLayer("Gate 2 · ripgrep");
                    f.setProofStatus("CONFIRMED");
                    f.setProof("ripgrep matched \"" + truncate(text, 160) + "\" at " + file + ":" + lineNo);
                    return f;
                });
            } catch (Exception ignored) {
                // Skip malformed JSON lines.
            }
        }
        return new ArrayList<>(byLocation.values());
    }

    private Hotspot classify(String text) {
        for (Hotspot h : HOTSPOTS) {
            try {
                if (java.util.regex.Pattern.compile(h.regex()).matcher(text).find()) {
                    return h;
                }
            } catch (Exception ignored) {
            }
        }
        return HOTSPOTS.get(0);
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, max) + "…";
    }
}
