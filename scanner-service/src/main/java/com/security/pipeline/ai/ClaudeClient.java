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

@Component
public class ClaudeClient {
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${anthropic.api-key:}")
    private String apiKey;

    @Value("${anthropic.model:claude-sonnet-5}")
    private String model;

    public boolean isConfigured() {
        return apiKey != null && !apiKey.isBlank();
    }

    public String complete(String system, String user, int maxTokens) {
        if (!isConfigured()) {
            return "";
        }

        try {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("model", model);
            body.put("max_tokens", Math.max(256, maxTokens));
            body.put("system", system);

            Map<String, Object> message = new LinkedHashMap<>();
            message.put("role", "user");
            message.put("content", List.of(Map.of("type", "text", "text", user)));
            body.put("messages", List.of(message));

            String json = objectMapper.writeValueAsString(body);
            HttpRequest request = HttpRequest.newBuilder(URI.create("https://api.anthropic.com/v1/messages"))
                    .header("x-api-key", apiKey)
                    .header("anthropic-version", "2023-06-01")
                    .header("content-type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .timeout(Duration.ofSeconds(45))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 300) {
                throw new IllegalStateException("Anthropic API error " + response.statusCode() + ": " + response.body());
            }

            JsonNode root = objectMapper.readTree(response.body());
            StringBuilder content = new StringBuilder();
            JsonNode items = root.path("content");
            if (items.isArray()) {
                for (JsonNode item : items) {
                    if (item.has("text")) {
                        content.append(item.get("text").asText());
                    }
                }
            }
            return content.length() > 0 ? content.toString() : root.toString();
        } catch (IOException | InterruptedException e) {
            Thread.currentThread().interrupt();
            return "";
        } catch (Exception e) {
            return "";
        }
    }

    public JsonNode completeJson(String system, String user, int maxTokens) {
        String text = complete(system, user, maxTokens);
        if (text == null || text.isBlank()) {
            return objectMapper.createObjectNode().put("error", "not_configured");
        }

        String normalized = text.trim();
        if (normalized.startsWith("```")) {
            normalized = normalized.replaceFirst("^```(?:json|JSON|yaml|YAML|yml|YML)?\\s*", "")
                    .replaceFirst("\\s*```$", "")
                    .trim();
        }

        try {
            return objectMapper.readTree(normalized);
        } catch (IOException e) {
            return objectMapper.createObjectNode()
                    .put("error", "unparseable")
                    .put("raw", text);
        }
    }
}
