package com.security.pipeline.service.gate1;

import java.nio.file.Path;

/**
 * A single Gate-1 static-analysis tool that runs over the checked-out repository. Implementations
 * shell out to the tool binary and translate its output into {@link Gate1Result}. When the binary
 * is not installed they return {@link Gate1Result#unavailable} rather than failing the scan, so the
 * pipeline degrades gracefully on hosts where a given tool is absent.
 */
public interface Gate1Tool {

    /** Stable id, e.g. {@code "semgrep"}. */
    String id();

    /** Label shown in the scan log / status view, e.g. {@code "Semgrep (SAST)"}. */
    String label();

    /** Execution order within Gate 1 (lower runs first). */
    int order();

    /** Runs the tool against {@code repoDir} and returns its result. Never returns {@code null}. */
    Gate1Result scan(Path repoDir);
}
