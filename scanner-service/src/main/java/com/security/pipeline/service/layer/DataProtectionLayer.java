package com.security.pipeline.service.layer;

import com.security.pipeline.ai.ClaudeClient;
import org.springframework.stereotype.Component;

/**
 * L3 - Data protection: secrets, PII, and cryptographic failures (OWASP A02:2021).
 */
@Component
public class DataProtectionLayer extends AbstractReviewLayer {

    public DataProtectionLayer(ClaudeClient claudeClient) {
        super(claudeClient);
    }

    @Override
    public String code() {
        return "L3";
    }

    @Override
    public String title() {
        return "Data protection";
    }

    @Override
    public int order() {
        return 3;
    }

    @Override
    protected String focus() {
        return "Focus exclusively on data protection and cryptographic failures: hard-coded secrets, API keys, "
                + "passwords or tokens; PII or sensitive data written to logs or error messages; missing encryption "
                + "in transit or at rest; weak, home-grown, or misconfigured cryptography; predictable randomness for "
                + "security purposes; and sensitive data exposed in responses, URLs, or caches.";
    }

    @Override
    protected String defaultCwe() {
        return "CWE-311";
    }

    @Override
    protected String defaultOwasp() {
        return "A02:2021";
    }
}
