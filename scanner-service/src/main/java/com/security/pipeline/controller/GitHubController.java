package com.security.pipeline.controller;

import com.security.pipeline.service.GitHubPrService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Read-only GitHub helpers for the dashboard's repo/branch pickers. The server holds the token
 * (never the browser), so private repos and branches can be listed without exposing credentials.
 * Both endpoints degrade to an empty list on error, letting the UI fall back to free-text entry.
 */
@RestController
@RequestMapping("/api/github")
public class GitHubController {

    private final GitHubPrService github;

    public GitHubController(GitHubPrService github) {
        this.github = github;
    }

    /** Repositories the configured token can see (empty when no token is set). */
    @GetMapping("/repos")
    public List<GitHubPrService.RepoInfo> repos() {
        return github.listRepos();
    }

    /** Branch names for the given repository URL or {@code owner/repo} slug. */
    @GetMapping("/branches")
    public List<String> branches(@RequestParam("repoUrl") String repoUrl) {
        return github.listBranches(repoUrl);
    }
}
