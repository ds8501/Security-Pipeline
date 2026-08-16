package com.security.pipeline.controller;

import jakarta.validation.constraints.NotBlank;

public record ScanRequest(
        @NotBlank(message = "repoUrl is required") String repoUrl,
        @NotBlank(message = "branch is required") String branch
) {
}
