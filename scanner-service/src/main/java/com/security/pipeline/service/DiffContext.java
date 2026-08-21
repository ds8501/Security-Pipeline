package com.security.pipeline.service;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record DiffContext(Path repoDir, String rawDiff, List<String> changedFiles, Map<String, String> fileContents) {
}
