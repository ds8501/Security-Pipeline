package com.security.pipeline.service.layer;

import com.security.pipeline.ai.ClaudeClient;
import org.springframework.stereotype.Component;

/**
 * L6 - Insecure design &amp; business-logic flaws (OWASP A04:2021).
 */
@Component
public class InsecureDesignLayer extends AbstractReviewLayer {

    public InsecureDesignLayer(ClaudeClient claudeClient) {
        super(claudeClient);
    }

    @Override
    public String code() {
        return "L6";
    }

    @Override
    public String title() {
        return "Insecure design & logic";
    }

    @Override
    public int order() {
        return 6;
    }

    @Override
    protected String focus() {
        return "Focus exclusively on insecure design and business-logic flaws: fail-open error handling, missing rate "
                + "limiting or anti-automation, race conditions and TOCTOU, insecure defaults, workflow steps that can be "
                + "skipped or replayed, trust boundaries assumed rather than enforced, and missing validation of "
                + "invariants (amounts, quantities, ownership, state transitions) that a scanner would not catch.";
    }

    @Override
    protected String defaultCwe() {
        return "CWE-657";
    }

    @Override
    protected String defaultOwasp() {
        return "A04:2021";
    }
}
