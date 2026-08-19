package com.security.pipeline.service.gate1;

import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;

/**
 * Holds the Gate-1 static-analysis tools in execution order. The scan pipeline iterates these
 * before the Gate-2 AI layers so that a single run covers both gates (tests/scanning first, then
 * the AI red-team review).
 */
@Service
public class Gate1Service {
    private final List<Gate1Tool> tools;

    public Gate1Service(List<Gate1Tool> tools) {
        this.tools = tools == null ? List.of() : tools.stream()
                .sorted(Comparator.comparingInt(Gate1Tool::order))
                .toList();
    }

    /** The Gate-1 tools in execution order. */
    public List<Gate1Tool> getTools() {
        return tools;
    }
}
