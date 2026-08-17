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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Provider-agnostic LLM client supporting both OpenAI-compatible APIs (Gemini, Groq, etc.)
 * and Anthropic. Class name is legacy for backward compatibility.
 */
@Component
public class ClaudeClient {
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${llm.base-url:https://generativelanguage.googleapis.com/v1beta/openai}")
    private String baseUrl;

    @Value("${llm.api-key:}")
    private String apiKey;

    @Value("${llm.model:gemini-2.5-flash}")
    private String model;

    private boolean anthropicNative;

    public ClaudeClient() {
    }

    private void ensureInitialized() {
        if (baseUrl == null) {
            baseUrl = "https://generativelanguage.googleapis.com/v1beta/openai";
        }
        baseUrl = baseUrl.replaceAll("/$", "");
        anthropicNative = baseUrl.contains("api.anthropic.com");
    }

    public boolean isConfigured() {
        return apiKey != null && !apiKey.isBlank();
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
                endpoint = baseUrl + "/messages";
            } else {
                json = buildOpenAIRequest(system, user, maxTokens);
                endpoint = baseUrl + "/chat/completions";
            }

            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(URI.create(endpoint))
                    .header("content-type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .timeout(Duration.ofMinutes(3));

            if (anthropicNative) {
                requestBuilder.header("x-api-key", apiKey)
                        .header("anthropic-version", "2023-06-01");
            } else {
                requestBuilder.header("authorization", "Bearer " + apiKey);
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

    private String buildOpenAIRequest(String system, String user, int maxTokens) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", model);
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
        body.put("model", model);
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
}
