package com.security.pipeline.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Provider-agnostic LLM client supporting both OpenAI-compatible APIs (Gemini, Groq, etc.)
 * and Anthropic. Class name is legacy for backward compatibility.
 */
@Component
public class ClaudeClient {
    private static final String DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai";
    private static final Set<String> ALLOWED_HOSTS = Set.of(
            "generativelanguage.googleapis.com",
            "api.anthropic.com",
            "api.openai.com",
            "api.groq.com"
    );

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${llm.base-url:}")
    private String baseUrl;

    @Value("${llm.api-key:}")
    private String apiKey;

    @Value("${llm.model:}")
    private String model;

    @Value("${anthropic.base-url:}")
    private String legacyBaseUrl;

    @Value("${anthropic.api-key:}")
    private String legacyApiKey;

    @Value("${anthropic.model:}")
    private String legacyModel;

    private boolean anthropicNative;
    private String resolvedBaseUrl;
    private String resolvedApiKey;
    private String resolvedModel;

    public ClaudeClient() {
    }

    private void ensureInitialized() {
        if (resolvedBaseUrl != null) {
            return;
        }

        String configuredApiKey = firstNonBlank(apiKey, legacyApiKey);
        String configuredModel = firstNonBlank(model, legacyModel);
        boolean legacyAnthropic = isBlank(apiKey) && !isBlank(legacyApiKey);

        String configuredBaseUrl = firstNonBlank(baseUrl, legacyBaseUrl);
        if (configuredBaseUrl == null) {
            configuredBaseUrl = legacyAnthropic ? "https://api.anthropic.com/v1" : DEFAULT_BASE_URL;
        }

        if (configuredModel == null) {
            configuredModel = legacyAnthropic ? "claude-sonnet-5" : "gemini-2.5-flash";
        }

        resolvedBaseUrl = normalizeBaseUrl(configuredBaseUrl);
        resolvedApiKey = configuredApiKey;
        resolvedModel = configuredModel;
        anthropicNative = URI.create(resolvedBaseUrl).getHost().equalsIgnoreCase("api.anthropic.com");
    }

    public boolean isConfigured() {
        ensureInitialized();
        return !isBlank(resolvedApiKey);
    }

    public String complete(String system, String user, int maxTokens) {
        ensureInitialized();
        if (!isConfigured()) {
            return "";
        }

        try {
            String json;
            String endpoint;

            if (anthropicNative) {
                json = buildAnthropicRequest(system, user, maxTokens);
                endpoint = resolvedBaseUrl + "/messages";
            } else {
                json = buildOpenAIRequest(system, user, maxTokens);
                endpoint = resolvedBaseUrl + "/chat/completions";
            }

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(URI.create(endpoint))
                    .header("content-type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .timeout(Duration.ofMinutes(3));

            if (anthropicNative) {
                requestBuilder.header("x-api-key", resolvedApiKey)
                        .header("anthropic-version", "2023-06-01");
            } else {
                requestBuilder.header("authorization", "Bearer " + resolvedApiKey);
            }

            HttpRequest request = requestBuilder.build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 429) {
                throw new IllegalStateException("Rate limited by the LLM provider. Wait a moment and retry.");
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalStateException("LLM API error " + response.statusCode() + ": " + response.body());
            }

            return extractContent(response.body(), anthropicNative);
        } catch (IllegalStateException e) {
            throw e;
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            return "";
        } catch (Exception e) {
            return "";
        }
    }

    static String normalizeBaseUrl(String configuredBaseUrl) {
        URI uri = URI.create(configuredBaseUrl.trim());
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null || !"https".equalsIgnoreCase(scheme)) {
            throw new IllegalStateException("LLM base URL must be an HTTPS endpoint.");
        }

        String normalizedHost = host.toLowerCase(Locale.ROOT);
        if (!ALLOWED_HOSTS.contains(normalizedHost)) {
            throw new IllegalStateException("Unsupported LLM provider endpoint: " + normalizedHost);
        }

        String normalized = uri.toString();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String buildOpenAIRequest(String system, String user, int maxTokens) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", resolvedModel);
        body.put("max_tokens", Math.max(256, maxTokens));
        body.put("temperature", 0);

        List<Map<String, String>> messages = List.of(
                Map.of("role", "system", "content", system),
                Map.of("role", "user", "content", user)
        );
        body.put("messages", messages);

        return objectMapper.writeValueAsString(body);
    }

    private String buildAnthropicRequest(String system, String user, int maxTokens) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", resolvedModel);
        body.put("max_tokens", Math.max(256, maxTokens));
        body.put("system", system);

        Map<String, Object> message = new LinkedHashMap<>();
        message.put("role", "user");
        message.put("content", user);
        body.put("messages", List.of(message));

        return objectMapper.writeValueAsString(body);
    }

    private String extractContent(String responseBody, boolean isAnthropic) throws IOException {
        JsonNode root = objectMapper.readTree(responseBody);

        if (isAnthropic) {
            StringBuilder content = new StringBuilder();
            JsonNode items = root.path("content");
            if (items.isArray()) {
                for (JsonNode item : items) {
                    if ("text".equals(item.path("type").asText())) {
                        content.append(item.path("text").asText());
                    }
                }
            }
            return content.length() > 0 ? content.toString() : root.toString();
        } else {
            return root.path("choices").path(0).path("message").path("content").asText("");
        }
    }

    public JsonNode completeJson(String system, String user, int maxTokens) {
        String text = complete(system, user, maxTokens);
        if (text == null || text.isBlank()) {
            return objectMapper.createObjectNode().put("error", "not_configured");
        }

        String normalized = stripMarkdown(text.trim());

        try {
            return objectMapper.readTree(normalized);
        } catch (IOException e) {
            return objectMapper.createObjectNode()
                    .put("error", "unparseable")
                    .put("raw", text);
        }
    }

    private String stripMarkdown(String text) {
        String result = text;
        if (result.startsWith("```")) {
            result = result.replaceFirst("^```(?:json|JSON|yaml|YAML|yml|YML)?\\s*", "")
                    .replaceFirst("\\s*```$", "")
                    .trim();
        }

        if (!result.startsWith("[") && !result.startsWith("{")) {
            int startIdx = Math.max(result.indexOf('['), result.indexOf('{'));
            int endIdx = Math.max(result.lastIndexOf(']'), result.lastIndexOf('}'));
            if (startIdx >= 0 && endIdx > startIdx) {
                result = result.substring(startIdx, endIdx + 1);
            }
        }

        return result;
    }

    public ObjectMapper mapper() {
        return objectMapper;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private String firstNonBlank(String primary, String secondary) {
        if (!isBlank(primary)) {
            return primary;
        }
        if (!isBlank(secondary)) {
            return secondary;
        }
        return null;
    }
}
