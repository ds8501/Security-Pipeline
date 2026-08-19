package com.security.pipeline.ai;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClaudeClientTest {
    @Test
    void normalizeBaseUrlTrimsTrailingSlash() {
        assertThat(ClaudeClient.normalizeBaseUrl("https://api.anthropic.com/"))
                .isEqualTo("https://api.anthropic.com");
    }

    @Test
    void normalizeBaseUrlAllowsKnownProviders() {
        assertThat(ClaudeClient.normalizeBaseUrl("https://generativelanguage.googleapis.com/v1beta/openai"))
                .isEqualTo("https://generativelanguage.googleapis.com/v1beta/openai");
        assertThat(ClaudeClient.normalizeBaseUrl("https://api.openai.com/v1"))
                .isEqualTo("https://api.openai.com/v1");
    }

    @Test
    void normalizeBaseUrlRejectsUnknownHosts() {
        assertThatThrownBy(() -> ClaudeClient.normalizeBaseUrl("https://attacker.example/v1"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Unsupported LLM provider endpoint");
    }
}
