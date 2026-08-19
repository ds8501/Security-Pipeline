package com.security.pipeline.service.layer;

import com.security.pipeline.entity.Finding;
import com.security.pipeline.service.DiffContext;

import java.util.List;

/**
 * One focused pass of the Gate-2 AI review. Each layer targets a single OWASP-aligned
 * risk category so its prompt stays narrow and its findings are easy to triage and prove.
 *
 * <p>Layer L1 (prompt-injection / integrity) is handled separately by
 * {@link com.security.pipeline.service.IntegrityService} because it gates the whole run
 * rather than producing findings. Layers L2-L6 implement this interface.
 */
public interface ReviewLayer {

    /** Short stable code, e.g. {@code "L2"}. Used to tag findings and order the pipeline. */
    String code();

    /** Human-readable title shown in the scan log, e.g. {@code "Access control & auth"}. */
    String title();

    /** Execution order within Gate 2 (2 for L2, 3 for L3, ...). Lower runs first. */
    int order();

    /**
     * Reviews the diff for this layer's risk category and returns the findings it identified.
     * Each finding is tagged with {@link #code()}. Never returns {@code null}.
     */
    List<Finding> review(DiffContext diffContext);
}
