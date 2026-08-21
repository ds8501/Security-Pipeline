package com.security.pipeline.controller;

import jakarta.validation.constraints.NotBlank;

public record ScanRequest(
        @NotBlank(message = "repoUrl is required") String repoUrl,
        @NotBlank(message = "branch is required") String branch,
        String baseBranch,
        String liveTarget,     // optional live URL for the Gate 2 DAST layer
        Boolean authorized     // must be true for DAST to run against liveTarget
) {
    public String baseBranchOrDefault() {
        return baseBranch == null || baseBranch.isBlank() ? "main" : baseBranch.trim();
    }
}
