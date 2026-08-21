package com.security.pipeline.service.layer;

import com.security.pipeline.ai.ClaudeClient;
import org.springframework.stereotype.Component;

/**
 * L7 - AI / LLM application security (OWASP LLM Top 10).
 *
 * <p>A differentiator: almost no CI security tool reviews the AI features teams now ship. This layer
 * hunts for LLM-specific risks — prompt injection sinks, untrusted input reaching a model or tool
 * call, secrets embedded in prompts, unsafe handling of model output, and over-broad tool exposure.
 */
@Component
public class AiSecurityLayer extends AbstractReviewLayer {

    public AiSecurityLayer(ClaudeClient claudeClient) {
        super(claudeClient);
    }

    @Override
    public String code() {
        return "L7";
    }

    @Override
    public String title() {
        return "AI / LLM application security";
    }

    @Override
    public int order() {
        return 7;
    }

    @Override
    protected String focus() {
        return "Focus exclusively on AI/LLM application security (OWASP LLM Top 10): "
                + "(1) PROMPT INJECTION — untrusted/user or retrieved content concatenated into a prompt or system "
                + "message without isolation; (2) INSECURE OUTPUT HANDLING — model output passed to eval/exec, a shell, "
                + "SQL, or rendered as HTML/markdown without sanitization (XSS/RCE via the model); (3) SECRETS IN PROMPTS — "
                + "API keys, tokens, or PII embedded in prompt templates or sent to the model; (4) EXCESSIVE AGENCY — "
                + "tools/functions exposed to the model that can delete data, call internal services (SSRF), or spend money "
                + "without authorization or human confirmation; (5) INSECURE RAG — untrusted documents indexed and fed back "
                + "as instructions; (6) missing output/schema validation, no rate/cost limits, and no guardrails on "
                + "model-driven actions. Only report AI/LLM-specific issues here.";
    }

    @Override
    protected String defaultCwe() {
        return "CWE-1427";
    }

    @Override
    protected String defaultOwasp() {
        return "LLM01:2025";
    }
}
