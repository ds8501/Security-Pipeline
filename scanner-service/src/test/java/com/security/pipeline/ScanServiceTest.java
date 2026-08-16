package com.security.pipeline;

import com.security.pipeline.entity.Scan;
import com.security.pipeline.service.ScanService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class ScanServiceTest {

    @Autowired
    private ScanService scanService;

    @Test
    void cleanScanPasses() {
        Scan scan = scanService.createScan("https://github.com/acme/clean-app", "main");

        assertThat(scan.getVerdict()).isEqualTo("PASS");
        assertThat(scan.getStatus()).isEqualTo("passed");
        assertThat(scan.getFindings()).isEmpty();
    }

    @Test
    void vulnerableScanBlocks() {
        Scan scan = scanService.createScan("https://github.com/acme/vulnerable-app", "main");

        assertThat(scan.getVerdict()).isEqualTo("BLOCKED");
        assertThat(scan.getStatus()).isEqualTo("blocked");
        assertThat(scan.getFindings()).hasSize(1);
        assertThat(scan.getFindings().get(0).getTitle()).contains("Sensitive user data is written to logs");
    }
}
