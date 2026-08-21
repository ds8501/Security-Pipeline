package com.security.pipeline.controller;

/**
 * Request to start a Gate-1 run.
 *   mode    - "github" | "local" | "auto" (default auto: GitHub if a token+repo are available, else local)
 *   ref     - branch/ref to check; optional, falls back to the configured default
 *   repo    - GitHub "owner/repo" to dispatch the workflow on (GitHub mode); optional, falls back to GITHUB_REPO
 *   repoUrl - clone URL for local mode; optional, falls back to the GitHub repo when set
 */
public record Gate1Request(String mode, String ref, String repo, String repoUrl) {
    public String modeOrAuto() {
        return mode == null || mode.isBlank() ? "auto" : mode.trim().toLowerCase();
    }
}
