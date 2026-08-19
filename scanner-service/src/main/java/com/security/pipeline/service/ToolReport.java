package com.security.pipeline.service;

import com.security.pipeline.entity.Finding;

import java.util.List;

/**
 * Generic result of running a supporting analysis tool (used by the Gate-2 ripgrep / tree-sitter
 * helpers). Mirrors the shape of the Gate-1 tool result but lives in the shared service package.
 *
 * @param status  one of PASS, FAIL, SKIPPED, UNAVAILABLE
 * @param summary short human-readable summary for the scan log / check row
 * @param findings findings produced by the tool (may be empty)
 */
public record ToolReport(String status, String summary, List<Finding> findings) {

    public static final String PASS = "PASS";
    public static final String FAIL = "FAIL";
    public static final String SKIPPED = "SKIPPED";
    public static final String UNAVAILABLE = "UNAVAILABLE";

    public static ToolReport unavailable(String why) {
        return new ToolReport(UNAVAILABLE, why, List.of());
    }

    public static ToolReport skipped(String why) {
        return new ToolReport(SKIPPED, why, List.of());
    }
}
