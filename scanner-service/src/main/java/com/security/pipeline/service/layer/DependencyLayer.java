package com.security.pipeline.service.layer;

import com.security.pipeline.ai.ClaudeClient;
import org.springframework.stereotype.Component;

/**
 * L5 - Vulnerable &amp; outdated components / supply chain (OWASP A06:2021).
 */
@Component
public class DependencyLayer extends AbstractReviewLayer {

    public DependencyLayer(ClaudeClient claudeClient) {
        super(claudeClient);
    }

    @Override
    public String code() {
        return "L5";
    }

    @Override
    public String title() {
        return "Dependencies & supply chain";
    }

    @Override
    public int order() {
        return 5;
    }

    @Override
    protected String focus() {
        return "Focus exclusively on vulnerable and outdated components and supply-chain risk: newly added or bumped "
                + "dependencies pinned to versions with known CVEs, unpinned or floating version ranges, packages pulled "
                + "from untrusted registries or URLs, typosquatting-style names, disabled integrity/lockfile checks, "
                + "and build scripts that download and execute code at install time.";
    }

    @Override
    protected String defaultCwe() {
        return "CWE-1104";
    }

    @Override
    protected String defaultOwasp() {
        return "A06:2021";
    }
}
