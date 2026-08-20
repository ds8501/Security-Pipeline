package com.security.pipeline.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Security integration test: the service must NOT expose a public config dump or an
 * unauthenticated admin surface.
 *
 * <p>These assertions FAIL while {@link VulnerableController} is present (the planted test
 * vulnerabilities expose those endpoints), and pass once it is removed — the same issues the
 * Gate-2 Red Team (DAST) flags at runtime.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityExposureIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void configJsonMustNotBeExposed() throws Exception {
        // Secure expectation: no public /config.json. Planted vuln returns 200 → this fails.
        mvc.perform(get("/config.json")).andExpect(status().isNotFound());
    }

    @Test
    void adminSurfaceMustRequireAuth() throws Exception {
        // Secure expectation: /admin is not publicly readable. Planted vuln returns 200 → this fails.
        mvc.perform(get("/admin")).andExpect(status().is4xxClientError());
    }
}
