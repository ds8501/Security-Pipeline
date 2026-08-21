package com.security.pipeline.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Thin GitHub Actions REST client (java.net.http, no extra deps). Dispatches the Gate-1 workflow
 * and reads back run + job status so the API can surface CI results in the UI.
 *
 * The token is server-side only (never accepted from the UI). The repo is passed per call so it
 * can come from the request, falling back to the configured GITHUB_REPO default.
 */
@Component
public class GitHubActionsClient {
    private static final String API = "https://api.github.com";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${gate1.github.token:}")
    private String token;

    @Value("${gate1.github.repo:}")
    private String configuredRepo;

    @Value("${gate1.github.workflow:security-gate-1.yml}")
    private String workflow;

    @Value("${gate1.github.ref:main}")
    private String defaultRef;

    public boolean hasToken() {
        return notBlank(token);
    }

    public String configuredRepo() {
        return configuredRepo;
    }

    public String workflow() {
        return workflow;
    }

    public String defaultRef() {
        return defaultRef;
    }

    /** Dispatches the configured workflow on the given repo + ref. Throws on failure. */
    public void dispatchWorkflow(String repo, String ref) throws Exception {
        String body = mapper.writeValueAsString(java.util.Map.of("ref", ref));
        HttpResponse<String> resp = send("POST",
                API + "/repos/" + repo + "/actions/workflows/" + workflow + "/dispatches", body);
        if (resp.statusCode() != 204) {
            throw new IllegalStateException("workflow_dispatch failed (" + resp.statusCode() + "): " + resp.body());
        }
    }

    /** Most recent workflow_dispatch run for this workflow on the given repo + ref, or null. */
    public JsonNode latestRun(String repo, String ref) throws Exception {
        String url = API + "/repos/" + repo + "/actions/workflows/" + workflow
                + "/runs?event=workflow_dispatch&branch=" + ref + "&per_page=10";
        HttpResponse<String> resp = send("GET", url, null);
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new IllegalStateException("list runs failed (" + resp.statusCode() + "): " + resp.body());
        }
        JsonNode runs = mapper.readTree(resp.body()).path("workflow_runs");
        return runs.isArray() && !runs.isEmpty() ? runs.get(0) : null;
    }

    public JsonNode getRun(String repo, long runId) throws Exception {
        HttpResponse<String> resp = send("GET", API + "/repos/" + repo + "/actions/runs/" + runId, null);
        return mapper.readTree(resp.body());
    }

    public JsonNode getJobs(String repo, long runId) throws Exception {
        HttpResponse<String> resp = send("GET", API + "/repos/" + repo + "/actions/runs/" + runId + "/jobs", null);
        return mapper.readTree(resp.body()).path("jobs");
    }

    private HttpResponse<String> send(String method, String url, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", "security-pipeline-gate1")
                .header("Authorization", "Bearer " + token)
                .timeout(Duration.ofSeconds(30));
        if ("POST".equals(method)) {
            b = b.header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
        } else {
            b = b.GET();
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
