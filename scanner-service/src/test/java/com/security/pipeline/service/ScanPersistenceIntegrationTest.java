package com.security.pipeline.service;

import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import com.security.pipeline.repository.FindingRepository;
import com.security.pipeline.repository.ScanRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Reproduces the exact conditions of the background review thread: a real Spring context with H2,
 * but persistence driven from a non-request thread so there is no Open-Session-In-View safety net.
 * This is where the original {@code LazyInitializationException} fired. The test locks down the
 * behaviour the fix depends on: no lazy failure off the request thread, findings receive database
 * ids, repeated saves do not duplicate them, and mutations survive a reload.
 */
@SpringBootTest
class ScanPersistenceIntegrationTest {

    @Autowired
    private ScanService scanService;

    @Autowired
    private ScanRepository scanRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Test
    void backgroundThreadPersistenceInitializesCollectionsAndAvoidsDuplicateFindings() throws Exception {
        Scan seed = new Scan();
        seed.setRepoUrl("https://example.test/repo");
        seed.setBranch("feature/login");
        seed.getLog().add("Queued for review");
        Long scanId = scanRepository.save(seed).getId();

        long findingsBefore = findingRepository.count();

        ExecutorService reviewThread = Executors.newSingleThreadExecutor();
        try {
            // Everything inside this lambda runs on a background thread with no ambient Hibernate
            // session — the same situation runReview() runs in.
            List<Long> assignedIds = reviewThread.submit(() -> {
                // 1. Load off the request thread. Collections must come back initialized.
                Scan scan = scanService.loadForReview(scanId);
                scan.setStatus("running");
                scan.getLog().add("Running security pipeline checks...");
                scan = scanService.persist(scan);

                // 2. Attach findings and persist (mirrors the AI review step).
                scan.getFindings().clear();
                for (int i = 0; i < 5; i++) {
                    Finding finding = new Finding();
                    finding.setTitle("issue-" + i);
                    finding.setSeverity(i == 0 ? "HIGH" : "LOW");
                    finding.setFile("src/File" + i + ".java");
                    finding.setDescription("desc-" + i);
                    finding.setProofStatus("UNPROVEN");
                    scan.addFinding(finding);
                }
                scan = scanService.persist(scan);
                List<Long> ids = scan.getFindings().stream().map(Finding::getId).toList();

                // 3. Mutate proof status on the persisted findings and persist again (proof step).
                //    A second save that carries findings must UPDATE, not re-insert.
                scan.getFindings().get(0).setProofStatus("CONFIRMED");
                scan.getFindings().get(0).setProof("semgrep matched");
                scan.setStatus("passed");
                scanService.persist(scan);

                return ids;
            }).get(30, TimeUnit.SECONDS); // .get() re-throws anything the background thread threw

            // No LazyInitializationException surfaced (else .get() above would have failed) and every
            // finding received a database id.
            assertThat(assignedIds).hasSize(5).allMatch(Objects::nonNull);

            // Two persist() calls carried the findings; there must be exactly 5 rows, not 10.
            assertThat(findingRepository.count() - findingsBefore).isEqualTo(5);

            // Mutations made off the request thread survived the reload.
            Scan reloaded = scanService.getScan(scanId);
            assertThat(reloaded.getStatus()).isEqualTo("passed");
            assertThat(reloaded.getFindings()).hasSize(5);
            assertThat(reloaded.getFindings())
                    .filteredOn(f -> "CONFIRMED".equalsIgnoreCase(f.getProofStatus()))
                    .singleElement()
                    .satisfies(f -> {
                        assertThat(f.getSeverity()).isEqualTo("HIGH");
                        assertThat(f.getProof()).isEqualTo("semgrep matched");
                    });
        } finally {
            reviewThread.shutdownNow();
        }
    }
}
