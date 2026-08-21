package com.security.pipeline.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Opens an auto-fix pull request via the GitHub REST API: it creates a new branch off the base,
 * commits the corrected files, and opens a PR. Gated on a token ({@code secgate.github-token} /
 * {@code GITHUB_TOKEN}); when absent the caller falls back to returning the patches for manual use.
 */
@Service
public class GitHubPrService {

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).build();
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${secgate.github-token:${GITHUB_TOKEN:}}")
    private String token;

    @Value("${secgate.github-api:https://api.github.com}")
    private String apiBase;

    public boolean isConfigured() {
        return token != null && !token.isBlank();
    }

    public record PrResult(boolean created, String url, String branch, String message) {
    }

    /**
     * Creates a branch off {@code baseBranch}, commits {@code fixedFiles} (path → new content), and
     * opens a PR. Never throws — returns a PrResult with {@code created=false} and a message on error.
     */
    public PrResult openPullRequest(String repoUrl, String baseBranch, Map<String, String> fixedFiles,
                                    String title, String body) {
        if (!isConfigured()) {
            return new PrResult(false, null, null, "No GitHub token configured (set GITHUB_TOKEN).");
        }
        if (fixedFiles == null || fixedFiles.isEmpty()) {
            return new PrResult(false, null, null, "No file changes to open a PR for.");
        }
        String slug = ownerRepo(repoUrl);
        if (slug == null) {
            return new PrResult(false, null, null, "Could not parse owner/repo from: " + repoUrl);
        }

        try {
            String base = (baseBranch == null || baseBranch.isBlank()) ? "main" : baseBranch.trim();
            String repoApi = apiBase + "/repos/" + slug;

            // 1) base branch head + its tree
            JsonNode ref = api("GET", repoApi + "/git/ref/heads/" + base, null);
            String baseSha = ref.path("object").path("sha").asText(null);
            if (baseSha == null) {
                return new PrResult(false, null, null, "Base branch '" + base + "' not found on the remote.");
            }
            JsonNode baseCommit = api("GET", repoApi + "/git/commits/" + baseSha, null);
            String baseTree = baseCommit.path("tree").path("sha").asText();

            // 2) blob + tree for each fixed file
            ArrayNode tree = mapper.createArrayNode();
            for (Map.Entry<String, String> e : fixedFiles.entrySet()) {
                ObjectNode blobReq = mapper.createObjectNode();
                blobReq.put("content", e.getValue());
                blobReq.put("encoding", "utf-8");
                JsonNode blob = api("POST", repoApi + "/git/blobs", blobReq);
                ObjectNode entry = tree.addObject();
                entry.put("path", e.getKey());
                entry.put("mode", "100644");
                entry.put("type", "blob");
                entry.put("sha", blob.path("sha").asText());
            }
            ObjectNode treeReq = mapper.createObjectNode();
            treeReq.put("base_tree", baseTree);
            treeReq.set("tree", tree);
            JsonNode newTree = api("POST", repoApi + "/git/trees", treeReq);

            // 3) commit + branch ref
            ObjectNode commitReq = mapper.createObjectNode();
            commitReq.put("message", title);
            commitReq.put("tree", newTree.path("sha").asText());
            commitReq.set("parents", mapper.createArrayNode().add(baseSha));
            JsonNode commit = api("POST", repoApi + "/git/commits", commitReq);

            String newBranch = "secgate/autofix-" + System.currentTimeMillis();
            ObjectNode refReq = mapper.createObjectNode();
            refReq.put("ref", "refs/heads/" + newBranch);
            refReq.put("sha", commit.path("sha").asText());
            api("POST", repoApi + "/git/refs", refReq);

            // 4) pull request
            ObjectNode prReq = mapper.createObjectNode();
            prReq.put("title", title);
            prReq.put("head", newBranch);
            prReq.put("base", base);
            prReq.put("body", body == null ? "" : body);
            JsonNode pr = api("POST", repoApi + "/pulls", prReq);
            String url = pr.path("html_url").asText(null);
            if (url == null) {
                return new PrResult(false, null, newBranch, "PR creation returned no URL: " + pr);
            }
            return new PrResult(true, url, newBranch, "Opened auto-fix PR with " + fixedFiles.size() + " file(s).");
        } catch (Exception e) {
            return new PrResult(false, null, null, "GitHub API error: " + e.getMessage());
        }
    }

    private JsonNode api(String method, String url, JsonNode body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .timeout(Duration.ofSeconds(30));
        if ("GET".equals(method)) {
            b.GET();
        } else {
            b.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body == null ? "{}" : body.toString()));
        }
        HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            throw new IllegalStateException("GitHub " + method + " " + url + " -> " + resp.statusCode() + ": " + resp.body());
        }
        return mapper.readTree(resp.body().isBlank() ? "{}" : resp.body());
    }

    /** Extracts {@code owner/repo} from https, ssh, or bare slug forms; strips any token/.git. */
    static String ownerRepo(String repoUrl) {
        if (repoUrl == null || repoUrl.isBlank()) {
            return null;
        }
        String s = repoUrl.trim();
        int at = s.lastIndexOf('@');
        if (at >= 0 && s.startsWith("http")) {
            // strip creds in https://user:token@github.com/...
            int scheme = s.indexOf("://");
            s = s.substring(0, scheme + 3) + s.substring(at + 1);
        }
        s = s.replaceFirst("^https?://[^/]+/", "")
                .replaceFirst("^git@[^:]+:", "")
                .replaceFirst("^ssh://git@[^/]+/", "");
        if (s.endsWith(".git")) {
            s = s.substring(0, s.length() - 4);
        }
        String[] parts = s.split("/");
        if (parts.length < 2) {
            return null;
        }
        return parts[parts.length - 2] + "/" + parts[parts.length - 1];
    }
}
