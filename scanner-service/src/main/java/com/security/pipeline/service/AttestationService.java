package com.security.pipeline.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

/**
 * Supply-chain attestation: produces a signed, verifiable statement of a scan's verdict (in a
 * DSSE-style envelope, in-toto Statement payload). A deploy gate can require a valid attestation
 * with {@code verdict == PASS} before promoting a commit — making the gate tamper-proof: nobody can
 * hand-edit a "PASS" without the signing key.
 *
 * <p>Signing uses HMAC-SHA256 with a configured key ({@code secgate.attestation.key}) — no external
 * infrastructure — while keeping the same envelope shape you'd later back with Sigstore/cosign.
 */
@Service
public class AttestationService {

    private static final String PAYLOAD_TYPE = "application/vnd.secgate.scan-verdict+json";
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${secgate.attestation.key:secgate-dev-signing-key-change-me}")
    private String signingKey;

    public record VerifyResult(boolean valid, String verdict, String message) {
    }

    /** Builds and signs a DSSE-style attestation envelope for a completed scan. */
    public String createEnvelope(Scan scan) throws Exception {
        ObjectNode statement = mapper.createObjectNode();
        statement.put("_type", "https://in-toto.io/Statement/v1");
        statement.put("predicateType", "https://secgate.dev/scan-verdict/v1");

        ArrayNode subject = statement.putArray("subject");
        ObjectNode subj = subject.addObject();
        subj.put("name", scan.getRepoUrl() == null ? "unknown" : scan.getRepoUrl());
        subj.put("branch", scan.getBranch() == null ? "unknown" : scan.getBranch());

        ObjectNode predicate = statement.putObject("predicate");
        predicate.put("tool", "secgate-pipeline");
        predicate.put("scanId", scan.getId());
        predicate.put("verdict", scan.getVerdict());
        predicate.put("status", scan.getStatus());
        predicate.put("summary", scan.getSummary());
        predicate.put("timestamp", Instant.now().toString());
        int confirmed = 0, high = 0;
        ArrayNode findings = predicate.putArray("findings");
        if (scan.getFindings() != null) {
            for (Finding f : scan.getFindings()) {
                ObjectNode fn = findings.addObject();
                fn.put("title", f.getTitle());
                fn.put("severity", f.getSeverity());
                fn.put("proofStatus", f.getProofStatus());
                if ("CONFIRMED".equalsIgnoreCase(f.getProofStatus())) {
                    confirmed++;
                }
                if ("HIGH".equalsIgnoreCase(f.getSeverity()) || "CRITICAL".equalsIgnoreCase(f.getSeverity())) {
                    high++;
                }
            }
        }
        predicate.put("confirmedFindings", confirmed);
        predicate.put("highOrCritical", high);

        byte[] payload = mapper.writeValueAsBytes(statement);
        String payloadB64 = Base64.getEncoder().encodeToString(payload);
        String sig = sign(payload);

        ObjectNode envelope = mapper.createObjectNode();
        envelope.put("payloadType", PAYLOAD_TYPE);
        envelope.put("payload", payloadB64);
        ArrayNode sigs = envelope.putArray("signatures");
        ObjectNode s = sigs.addObject();
        s.put("alg", "HmacSHA256");
        s.put("keyid", keyId());
        s.put("sig", sig);
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(envelope);
    }

    /** Verifies an attestation envelope's signature and returns the attested verdict. */
    public VerifyResult verify(String envelopeJson) {
        try {
            JsonNode env = mapper.readTree(envelopeJson);
            String payloadB64 = env.path("payload").asText(null);
            String sig = env.path("signatures").path(0).path("sig").asText(null);
            if (payloadB64 == null || sig == null) {
                return new VerifyResult(false, null, "Malformed envelope (missing payload or signature).");
            }
            byte[] payload = Base64.getDecoder().decode(payloadB64);
            String expected = sign(payload);
            if (!constantTimeEquals(expected, sig)) {
                return new VerifyResult(false, null, "Signature mismatch — attestation is invalid or tampered.");
            }
            JsonNode statement = mapper.readTree(payload);
            String verdict = statement.path("predicate").path("verdict").asText("UNKNOWN");
            return new VerifyResult(true, verdict, "Signature valid.");
        } catch (Exception e) {
            return new VerifyResult(false, null, "Verification error: " + e.getMessage());
        }
    }

    private String sign(byte[] payload) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(signingKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(payload));
    }

    private String keyId() {
        // Non-secret identifier for the signing key (first bytes of its own hash).
        try {
            byte[] h = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(signingKey.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(h).substring(0, 12);
        } catch (Exception e) {
            return "unknown";
        }
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < a.length(); i++) {
            r |= a.charAt(i) ^ b.charAt(i);
        }
        return r == 0;
    }
}
