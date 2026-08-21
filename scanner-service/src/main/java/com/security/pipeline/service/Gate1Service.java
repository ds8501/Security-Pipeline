package com.security.pipeline.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.security.pipeline.controller.Gate1Request;
import com.security.pipeline.entity.Gate1Check;
import com.security.pipeline.entity.Gate1Run;
import com.security.pipeline.store.Gate1Store;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Runs Gate 1 either by dispatching the GitHub Actions workflow (when a token is configured on the
 * server and a repo is known) or by running the tools locally. Both paths update an in-memory
 * {@link Gate1Run} the UI polls. The GitHub token is server-side only; the repo can come from the
 * request (falling back to the configured GITHUB_REPO).
 */
@Service
public class Gate1Service {
    private final Gate1Store store;
    private final GitHubActionsClient github;
    private final LocalGateRunner localRunner;
    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    public Gate1Service(Gate1Store store, GitHubActionsClient github, LocalGateRunner localRunner) {
        this.store = store;
        this.github = github;
        this.localRunner = localRunner;
    }

    public List<Gate1Run> getRuns() {
        return store.findAllByCreatedAtDesc();
    }

    public Gate1Run getRun(Long id) {
        return store.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Gate-1 run not found: " + id));
    }

    public Gate1Run start(Gate1Request request) {
        // The repo field accepts either "owner/name" or a full GitHub URL — normalize both.
        String rawRepo = firstNonBlank(request.repo(), github.configuredRepo());
        String repo = toOwnerRepo(rawRepo);                                  // "owner/name" or null
        String repoUrl = firstNonBlank(request.repoUrl(), toCloneUrl(rawRepo)); // clone URL or null

        String mode = request.modeOrAuto();
        if ("auto".equals(mode)) {
            mode = (github.hasToken() && repo != null) ? "github" : "local";
        }

        Gate1Run run = new Gate1Run();
        run.setMode(mode);
        run.setRef(firstNonBlank(request.ref(), github.defaultRef()));
        run.setRepoUrl(repoUrl);
        run.getLog().add("Gate 1 queued (mode=" + mode + (repo != null ? ", repo=" + repo : "") + ")");
        store.save(run);

        final String selectedMode = mode;
        final String selectedRepo = repo;
        executor.submit(() -> {
            if ("github".equals(selectedMode)) {
                runGithub(run, selectedRepo);
            } else {
                if (run.getRepoUrl() == null || run.getRepoUrl().isBlank()) {
                    fail(run, "Local mode needs a repoUrl (none provided and no GitHub repo configured).");
                    return;
                }
                localRunner.run(run);
            }
        });
        return run;
    }

    private void runGithub(Gate1Run run, String repo) {
        try {
            if (!github.hasToken()) {
                fail(run, "GitHub token not set on the server. Set GITHUB_TOKEN (a PAT with 'actions:write') and restart.");
                return;
            }
            if (repo == null || repo.isBlank()) {
                fail(run, "No repo to target. Pass \"repo\":\"owner/name\" in the request or set GITHUB_REPO.");
                return;
            }

            run.setStatus("running");
            run.getLog().add("Dispatching workflow " + github.workflow() + " on " + repo + "@" + run.getRef());

            Long beforeId = idOf(github.latestRun(repo, run.getRef()));
            github.dispatchWorkflow(repo, run.getRef());

            // Wait for the new run to appear.
            JsonNode newRun = null;
            for (int i = 0; i < 30 && newRun == null; i++) {
                Thread.sleep(3000);
                JsonNode latest = github.latestRun(repo, run.getRef());
                Long latestId = idOf(latest);
                if (latestId != null && !latestId.equals(beforeId)) {
                    newRun = latest;
                }
            }
            if (newRun == null) {
                fail(run, "Timed out waiting for the dispatched run to appear.");
                return;
            }

            long runId = newRun.get("id").asLong();
            run.setRunUrl(newRun.path("html_url").asText(null));
            run.getLog().add("Run started: " + run.getRunUrl());

            // Follow the run to completion, refreshing job -> check mapping.
            String status = newRun.path("status").asText("queued");
            for (int i = 0; i < 200 && !"completed".equals(status); i++) {
                syncChecks(run, github.getJobs(repo, runId));
                Thread.sleep(4000);
                JsonNode r = github.getRun(repo, runId);
                status = r.path("status").asText("queued");
                run.setRunUrl(r.path("html_url").asText(run.getRunUrl()));
            }
            syncChecks(run, github.getJobs(repo, runId));

            JsonNode finalRun = github.getRun(repo, runId);
            String conclusion = finalRun.path("conclusion").asText("");
            run.setStatus("completed");
            run.setConclusion("success".equals(conclusion) ? "PASS" : "BLOCKED");
            run.setSummary("GitHub Actions run " + ("success".equals(conclusion) ? "passed" : "concluded: " + conclusion));
            run.getLog().add("Run completed: " + conclusion);
        } catch (Exception e) {
            fail(run, "GitHub dispatch/poll failed: " + e.getMessage());
        }
    }

    /** Replace the checks list with the current jobs (name/status/conclusion/url). */
    private void syncChecks(Gate1Run run, JsonNode jobs) {
        if (jobs == null || !jobs.isArray()) {
            return;
        }
        run.getChecks().clear();
        for (JsonNode job : jobs) {
            Gate1Check check = new Gate1Check(job.path("name").asText("job"));
            check.setStatus(job.path("status").asText("queued"));
            check.setConclusion(job.path("conclusion").isNull() ? null : job.path("conclusion").asText(null));
            check.setUrl(job.path("html_url").asText(null));
            run.getChecks().add(check);
        }
    }

    private void fail(Gate1Run run, String message) {
        run.setStatus("error");
        run.setConclusion("ERROR");
        run.setSummary(message);
        run.getLog().add("ERROR: " + message);
    }

    private Long idOf(JsonNode run) {
        return run == null || run.get("id") == null ? null : run.get("id").asLong();
    }

    private String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a.trim();
        }
        return b != null && !b.isBlank() ? b.trim() : null;
    }

    /** Accepts "owner/name" or a GitHub URL and returns "owner/name" (or null). */
    static String toOwnerRepo(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        raw = raw.trim();
        if (raw.contains("github.com")) {
            String path = raw.replaceFirst("^.*github\\.com[/:]", "")
                    .replaceFirst("\\.git$", "")
                    .replaceFirst("/+$", "");
            String[] parts = path.split("/");
            return parts.length >= 2 ? parts[0] + "/" + parts[1] : null;
        }
        String cleaned = raw.replaceFirst("\\.git$", "").replaceFirst("/+$", "");
        return cleaned.contains("/") ? cleaned : null;
    }

    /** Accepts "owner/name" or a URL and returns a clonable HTTPS URL (or null). */
    static String toCloneUrl(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        raw = raw.trim();
        if (raw.contains("://") || raw.startsWith("git@")) {
            return raw.endsWith(".git") ? raw : raw + ".git";
        }
        String ownerRepo = toOwnerRepo(raw);
        return ownerRepo != null ? "https://github.com/" + ownerRepo + ".git" : null;
    }
}
