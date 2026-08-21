package com.security.pipeline.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Enables cross-origin requests to the API so the standalone UI (served on a different origin/port,
 * e.g. http://localhost:3000) can call this backend. Origins are configurable via
 * {@code secgate.cors.allowed-origins} (comma-separated); defaults to any origin for local dev.
 */
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Value("${secgate.cors.allowed-origins:*}")
    private String[] allowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOriginPatterns(allowedOrigins)
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .maxAge(3600);
    }
}
