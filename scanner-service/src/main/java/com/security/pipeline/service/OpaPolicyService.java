package com.security.pipeline.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Gate-2 "deciding block vs allow" tool (design doc: OPA/Conftest). Evaluates the block/allow
 * decision against a Rego policy ({@code policy/verdict.rego}) using the {@code opa} binary, instead
 * of relying only on the hardcoded Java logic. Returns {@link Optional#empty()} when OPA is not
 * installed so the caller can fall back to the built-in decision.
 */
@Service
public class OpaPolicyService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${secgate.opa-binary:opa}")
    private String opaBinary;

    @Value("${secgate.opa.policy-classpath:policy/verdict.rego}")
    private String policyClasspath;

    @Value("${secgate.opa.query:data.secgate.block}")
    private String query;

    /**
     * Evaluates the policy and returns whether the merge should be blocked, or empty if OPA could
     * not be run (missing binary, missing policy, evaluation error) — the caller then falls back.
     */
    public Optional<Boolean> evaluateBlock(Scan scan, boolean injectionDetected, boolean suspiciousClean) {
        Path policyFile = null;
        try {
            policyFile = materializePolicy();
            if (policyFile == null) {
                return Optional.empty();
            }

            String input = buildInput(scan, injectionDetected, suspiciousClean);

            ProcessBuilder pb = new ProcessBuilder(
                    opaBinary, "eval", "--format", "json",
                    "--data", policyFile.toString(),
                    "--stdin-input", query);
            pb.redirectErrorStream(true);

            Process process;
            try {
                process = pb.start();
            } catch (Exception e) {
                return Optional.empty(); // opa not installed
            }

            process.getOutputStream().write(input.getBytes(StandardCharsets.UTF_8));
            process.getOutputStream().close();

            boolean completed = process.waitFor(30, TimeUnit.SECONDS);
            if (!completed) {
                process.destroyForcibly();
                return Optional.empty();
            }
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (process.exitValue() != 0) {
                return Optional.empty();
            }

            JsonNode root = objectMapper.readTree(output);
            JsonNode value = root.path("result").path(0).path("expressions").path(0).path("value");
            if (value.isBoolean()) {
                return Optional.of(value.asBoolean());
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        } finally {
            if (policyFile != null) {
                try {
                    Files.deleteIfExists(policyFile);
                } catch (Exception ignored) {
                }
            }
        }
    }

    private Path materializePolicy() {
        try (InputStream in = new ClassPathResource(policyClasspath).getInputStream()) {
            Path temp = Files.createTempFile("secgate-policy-", ".rego");
            Files.write(temp, in.readAllBytes());
            return temp;
        } catch (Exception e) {
            return null;
        }
    }

    private String buildInput(Scan scan, boolean injectionDetected, boolean suspiciousClean) {
        ObjectNode input = objectMapper.createObjectNode();
        input.put("injectionDetected", injectionDetected);
        input.put("suspiciousClean", suspiciousClean);
        ArrayNode findings = input.putArray("findings");
        List<Finding> safe = scan.getFindings() == null ? List.of() : scan.getFindings();
        for (Finding f : safe) {
            ObjectNode node = findings.addObject();
            node.put("severity", f.getSeverity() == null ? "LOW" : f.getSeverity());
            node.put("proofStatus", f.getProofStatus() == null ? "UNPROVEN" : f.getProofStatus());
        }
        return input.toString();
    }
}
