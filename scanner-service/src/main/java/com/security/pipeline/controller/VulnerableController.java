package com.security.pipeline.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ⚠️⚠️⚠️  INTENTIONAL TEST VULNERABILITIES — DO NOT MERGE TO MAIN  ⚠️⚠️⚠️
 *
 * Planted on {@code test-branch} to validate that the security pipeline catches them:
 *  - the Gate-2 Red Team (DAST) probe flags the exposed endpoints at runtime, and
 *  - {@code SecurityExposureIntegrationTest} fails because these endpoints are exposed.
 *
 * Every endpoint/field below is deliberately insecure. Delete this class to remediate.
 */
@RestController
public class VulnerableController {

    // VULN 1 (CWE-798: hardcoded credentials in source) — Gitleaks / ripgrep hotspots.
    private static final String ADMIN_PASSWORD = "SuperSecret123!";
    private static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    /**
     * VULN 2 (CWE-200 / CWE-538: sensitive information exposure) — unauthenticated config dump.
     * The Red Team probes {@code /config.json}; a 200 with a body triggers a HIGH finding.
     */
    @GetMapping("/config.json")
    public Map<String, Object> config() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("adminPassword", ADMIN_PASSWORD);
        m.put("awsSecretAccessKey", AWS_SECRET_ACCESS_KEY);
        m.put("dbUrl", "jdbc:postgresql://db:5432/app?user=admin&password=" + ADMIN_PASSWORD);
        return m;
    }

    /**
     * VULN 3 (CWE-306: missing authentication for a critical function) — open admin surface.
     * The Red Team probes {@code /admin}; a 200 triggers a MEDIUM "unauthenticated surface" finding.
     */
    @GetMapping("/admin")
    public Map<String, Object> admin() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("message", "admin access granted (no authentication required)");
        m.put("users", List.of("alice", "bob", "root"));
        return m;
    }
}
