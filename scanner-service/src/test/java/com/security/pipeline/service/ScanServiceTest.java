package com.security.pipeline.service;

import com.security.pipeline.ai.ClaudeClient;
import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ScanServiceTest {
    private final ScanService scanService = new ScanService(null, null, null, null, null, new ClaudeClient());
    private final IntegrityService integrityService = new IntegrityService(new ClaudeClient());

    @Test
    void noFindingsPasses() {
        Scan scan = new Scan();
        scanService.decideVerdict(scan, false, false);

        assertThat(scan.getVerdict()).isEqualTo("PASS");
        assertThat(scan.getStatus()).isEqualTo("passed");
        assertThat(scan.getSummary()).isEqualTo("0 confirmed, 0 unproven");
    }

    @Test
    void confirmedHighBlocks() {
        Scan scan = new Scan();
        Finding finding = new Finding();
        finding.setSeverity("HIGH");
        finding.setProofStatus("CONFIRMED");
        scan.addFinding(finding);

        scanService.decideVerdict(scan, false, false);

        assertThat(scan.getVerdict()).isEqualTo("BLOCKED");
        assertThat(scan.getStatus()).isEqualTo("blocked");
    }

    @Test
    void unprovenCriticalDoesNotBlock() {
        Scan scan = new Scan();
        Finding finding = new Finding();
        finding.setSeverity("CRITICAL");
        finding.setProofStatus("UNPROVEN");
        scan.addFinding(finding);

        scanService.decideVerdict(scan, false, false);

        assertThat(scan.getVerdict()).isEqualTo("PASS");
        assertThat(scan.getStatus()).isEqualTo("passed");
    }

    @Test
    void confirmedLowDoesNotBlock() {
        Scan scan = new Scan();
        Finding finding = new Finding();
        finding.setSeverity("LOW");
        finding.setProofStatus("CONFIRMED");
        scan.addFinding(finding);

        scanService.decideVerdict(scan, false, false);

        assertThat(scan.getVerdict()).isEqualTo("PASS");
        assertThat(scan.getStatus()).isEqualTo("passed");
    }

    @Test
    void injectionAlwaysBlocks() {
        Scan scan = new Scan();
        scanService.decideVerdict(scan, true, false);

        assertThat(scan.getVerdict()).isEqualTo("BLOCKED");
        assertThat(scan.getStatus()).isEqualTo("blocked");
    }

    @Test
    void suspiciousCleanAlwaysBlocks() {
        Scan scan = new Scan();
        scanService.decideVerdict(scan, false, true);

        assertThat(scan.getVerdict()).isEqualTo("BLOCKED");
        assertThat(scan.getStatus()).isEqualTo("blocked");
    }

    @Test
    void suspiciousCleanVerdictFlagsSensitivePaths() {
        assertThat(integrityService.suspiciousCleanVerdict(List.of("src/auth/LoginController.java"), 0)).isTrue();
        assertThat(integrityService.suspiciousCleanVerdict(List.of("src/ui/App.java"), 0)).isFalse();
        assertThat(integrityService.suspiciousCleanVerdict(List.of("src/auth/LoginController.java"), 1)).isFalse();
    }
}
