package com.security.pipeline.controller;

import com.security.pipeline.entity.Scan;
import com.security.pipeline.service.AttestationService;
import com.security.pipeline.service.ScanService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Endpoints for the supply-chain attestation: fetch a signed verdict envelope for a scan, and
 * verify one (the deploy gate calls verify and requires {@code valid && verdict == PASS}).
 */
@RestController
public class AttestationController {

    private final ScanService scanService;
    private final AttestationService attestationService;

    public AttestationController(ScanService scanService, AttestationService attestationService) {
        this.scanService = scanService;
        this.attestationService = attestationService;
    }

    /** Signed DSSE-style attestation envelope for a completed scan. */
    @GetMapping(value = "/api/scans/{id}/attestation", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> attestation(@PathVariable Long id) {
        Scan scan;
        try {
            scan = scanService.getScan(id);
        } catch (Exception e) {
            return ResponseEntity.status(404).body("{\"error\":\"Scan not found: " + id + "\"}");
        }
        try {
            return ResponseEntity.ok(attestationService.createEnvelope(scan));
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\"error\":\"Could not sign attestation: " + e.getMessage() + "\"}");
        }
    }

    /** Verifies a posted attestation envelope. The deploy gate requires valid && verdict == PASS. */
    @PostMapping(value = "/api/attestation/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> verify(@RequestBody String envelopeJson) {
        AttestationService.VerifyResult r = attestationService.verify(envelopeJson);
        boolean deployAllowed = r.valid() && "PASS".equalsIgnoreCase(r.verdict());
        return ResponseEntity.ok(Map.of(
                "valid", r.valid(),
                "verdict", r.verdict() == null ? "UNKNOWN" : r.verdict(),
                "deployAllowed", deployAllowed,
                "message", r.message()
        ));
    }
}
