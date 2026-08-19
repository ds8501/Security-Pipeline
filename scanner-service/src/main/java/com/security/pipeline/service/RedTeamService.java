package com.security.pipeline.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.pipeline.entity.RedTeamFinding;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.concurrent.TimeUnit;

/**
 * Live DAST probing used by Gate 2's red-team layer. Every check is non-destructive: GET/HEAD-only
 * recon (security headers, TLS, exposed sensitive paths, unauthenticated admin surface) plus an
 * optional {@code nuclei} scan when installed. The caller is responsible for authorization and for
 * supplying only in-scope (public, owned) targets — this class just probes what it is given.
 */
@Service
public class RedTeamService {
    private static final List<String> SENSITIVE_PATHS = List.of(
            "/.env", "/.git/HEAD", "/.aws/credentials", "/config.json",
            "/actuator/env", "/actuator/health", "/server-status", "/phpinfo.php");
    private static final List<String> ADMIN_PATHS = List.of("/admin", "/actuator", "/manage");

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    /** Probe each target and return findings. {@code log} receives progress lines (may be null). */
    public List<RedTeamFinding> probe(List<String> targets, Consumer<String> log) {
        List<RedTeamFinding> findings = new ArrayList<>();
        for (String target : targets) {
            if (log != null) {
                log.accept("DAST probing " + target);
            }
            probeSecurityHeadersAndTls(findings, target, log);
            probeSensitivePaths(findings, target);
            probeAdminSurface(findings, target);
            runNuclei(findings, target, log);
        }
        return findings;
    }

    private void probeSecurityHeadersAndTls(List<RedTeamFinding> out, String target, Consumer<String> log) {
        HttpResponse<Void> resp = head(target);
        if (resp == null) {
            if (log != null) {
                log.accept("  unreachable: " + target);
            }
            return;
        }
        if (target.startsWith("http://")) {
            add(out, "No TLS (plaintext HTTP)", "HIGH", target, "TLS",
                    "Service served over http://", "Serve over HTTPS and redirect HTTP→HTTPS.");
        }
        var h = resp.headers();
        checkHeader(out, target, h.firstValue("content-security-policy").isPresent(), "Content-Security-Policy", "MEDIUM");
        checkHeader(out, target, h.firstValue("strict-transport-security").isPresent(), "Strict-Transport-Security", "MEDIUM");
        checkHeader(out, target, h.firstValue("x-content-type-options").isPresent(), "X-Content-Type-Options", "LOW");
        checkHeader(out, target, h.firstValue("x-frame-options").isPresent() || h.firstValue("content-security-policy").isPresent(), "X-Frame-Options/frame-ancestors", "LOW");
    }

    private void checkHeader(List<RedTeamFinding> out, String target, boolean present, String header, String severity) {
        if (!present) {
            add(out, "Missing " + header, severity, target, "Security headers",
                    header + " not set", "Add the " + header + " response header.");
        }
    }

    private void probeSensitivePaths(List<RedTeamFinding> out, String target) {
        for (String path : SENSITIVE_PATHS) {
            HttpResponse<String> r = get(join(target, path));
            if (r != null && r.statusCode() == 200 && r.body() != null && !r.body().isBlank()) {
                add(out, "Exposed sensitive path " + path, "HIGH", target, "Exposed path",
                        "GET " + path + " → 200", "Block public access to " + path + ".");
            }
        }
    }

    private void probeAdminSurface(List<RedTeamFinding> out, String target) {
        for (String path : ADMIN_PATHS) {
            HttpResponse<String> r = get(join(target, path));
            if (r != null && r.statusCode() == 200) {
                add(out, "Unauthenticated surface " + path, "MEDIUM", target, "Access control",
                        "GET " + path + " → 200 without auth", "Require authentication on " + path + ".");
            }
        }
    }

    private void runNuclei(List<RedTeamFinding> out, String target, Consumer<String> log) {
        try {
            Process p = new ProcessBuilder("nuclei", "-u", target, "-jsonl", "-silent", "-duc")
                    .redirectErrorStream(true).start();
            String output = new String(p.getInputStream().readAllBytes());
            if (!p.waitFor(180, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return;
            }
            for (String line : output.split("\\R")) {
                if (line.isBlank() || !line.trim().startsWith("{")) {
                    continue;
                }
                JsonNode n = mapper.readTree(line);
                add(out, n.path("info").path("name").asText("nuclei finding"),
                        n.path("info").path("severity").asText("info").toUpperCase(),
                        target, "nuclei", n.path("matched-at").asText(""), "Review the nuclei template output.");
            }
        } catch (Exception toolMissingOrError) {
            if (log != null) {
                log.accept("  nuclei not run (" + toolMissingOrError.getMessage() + ")");
            }
        }
    }

    private HttpResponse<Void> head(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofSeconds(10)).build();
            return http.send(req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            return null;
        }
    }

    private HttpResponse<String> get(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url)).GET()
                    .timeout(Duration.ofSeconds(10)).build();
            return http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            return null;
        }
    }

    private String join(String base, String path) {
        return base.replaceFirst("/+$", "") + path;
    }

    private void add(List<RedTeamFinding> out, String title, String sev, String target, String cat, String ev, String rec) {
        out.add(new RedTeamFinding(title, sev, target, cat, ev, rec));
    }
}
