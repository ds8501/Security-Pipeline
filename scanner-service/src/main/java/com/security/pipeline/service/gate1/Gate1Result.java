package com.security.pipeline.service.gate1;

import com.security.pipeline.entity.Finding;

import java.util.List;

/**
 * Outcome of running one Gate-1 tool over the checked-out repository.
 *
 * @param tool      tool id (e.g. {@code "semgrep"})
 * @param status    one of PASS, FAIL, SKIPPED, UNAVAILABLE
 * @param summary   short human-readable summary for the scan log / check row
 * @param findings  findings produced by the tool (already tagged, may be empty)
 */
public record Gate1Result(String tool, String status, String summary, List<Finding> findings) {

    public static final String PASS = "PASS";
    public static final String FAIL = "FAIL";
    public static final String SKIPPED = "SKIPPED";
    public static final String UNAVAILABLE = "UNAVAILABLE";

    public static Gate1Result unavailable(String tool, String why) {
        return new Gate1Result(tool, UNAVAILABLE, why, List.of());
    }

    public static Gate1Result skipped(String tool, String why) {
        return new Gate1Result(tool, SKIPPED, why, List.of());
    }
}
