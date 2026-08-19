package com.security.pipeline.service.layer;

import com.security.pipeline.ai.ClaudeClient;
import org.springframework.stereotype.Component;

/**
 * L4 - Injection &amp; unsafe input handling (OWASP A03:2021).
 */
@Component
public class InjectionLayer extends AbstractReviewLayer {

    public InjectionLayer(ClaudeClient claudeClient) {
        super(claudeClient);
    }

    @Override
    public String code() {
        return "L4";
    }

    @Override
    public String title() {
        return "Injection & unsafe input";
    }

    @Override
    public int order() {
        return 4;
    }

    @Override
    protected String focus() {
        return "Focus exclusively on injection and unsafe input handling: SQL/NoSQL injection, OS command injection, "
                + "LDAP or expression-language injection, cross-site scripting (XSS), path traversal, server-side "
                + "template injection, unsafe deserialization, and any place user-controlled input reaches an "
                + "interpreter, query, file path, or process without parameterization, validation, or encoding.";
    }

    @Override
    protected String defaultCwe() {
        return "CWE-74";
    }

    @Override
    protected String defaultOwasp() {
        return "A03:2021";
    }
}
