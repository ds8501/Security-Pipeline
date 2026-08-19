package com.security.pipeline.service.layer;

import com.security.pipeline.ai.ClaudeClient;
import org.springframework.stereotype.Component;

/**
 * L2 - Broken access control &amp; authentication (OWASP A01:2021).
 */
@Component
public class AccessControlLayer extends AbstractReviewLayer {

    public AccessControlLayer(ClaudeClient claudeClient) {
        super(claudeClient);
    }

    @Override
    public String code() {
        return "L2";
    }

    @Override
    public String title() {
        return "Access control & auth";
    }

    @Override
    public int order() {
        return 2;
    }

    @Override
    protected String focus() {
        return "Focus exclusively on broken access control and authentication: missing or insufficient authorization "
                + "checks, insecure direct object references (IDOR), privilege escalation, path/tenant isolation gaps, "
                + "unauthenticated endpoints, forced browsing, JWT/session validation flaws, and CORS or CSRF weaknesses "
                + "that let a user act outside their intended permissions.";
    }

    @Override
    protected String defaultCwe() {
        return "CWE-284";
    }

    @Override
    protected String defaultOwasp() {
        return "A01:2021";
    }
}
