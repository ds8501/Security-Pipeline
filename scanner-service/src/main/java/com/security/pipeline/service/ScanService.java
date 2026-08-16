package com.security.pipeline.service;

import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import com.security.pipeline.repository.ScanRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class ScanService {
    private final ScanRepository scanRepository;

    public ScanService(ScanRepository scanRepository) {
        this.scanRepository = scanRepository;
    }

    public List<Scan> getScans() {
        return scanRepository.findAllByOrderByCreatedAtDesc();
    }

    public Scan getScan(Long id) {
        return scanRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + id));
    }

    @Transactional
    public Scan createScan(String repoUrl, String branch) {
        String normalizedRepo = repoUrl == null ? "" : repoUrl.trim();
        String normalizedBranch = branch == null ? "" : branch.trim();

        if (normalizedRepo.isBlank()) {
            throw new IllegalArgumentException("repoUrl is required");
        }
        if (normalizedBranch.isBlank()) {
            throw new IllegalArgumentException("branch is required");
        }

        Scan scan = new Scan();
        scan.setRepoUrl(normalizedRepo);
        scan.setBranch(normalizedBranch);
        scan.setStatus("queued");
        scan.setVerdict("PENDING");
        scan.setSummary("Waiting for the security review pipeline to start.");
        scan.getLog().add("Queued for review");
        scanRepository.save(scan);

        runReview(scan.getId());
        return scanRepository.findById(scan.getId()).orElse(scan);
    }

    @Transactional
    public void runReview(Long scanId) {
        try {
            Thread.sleep(1200L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + scanId));

        scan.setStatus("running");
        scan.getLog().add("Repository diff is being analyzed.");
        scan.setSummary("Running the investigation and proof checks.");
        scanRepository.save(scan);

        try {
            Thread.sleep(1300L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        String signal = (scan.getRepoUrl() + " " + scan.getBranch()).toLowerCase();
        boolean isHiddenInstruction = signal.contains("hidden") || signal.contains("instruction") || signal.contains("prompt");
        boolean isVulnerable = signal.contains("vulnerable") || signal.contains("secret") || signal.contains("leak") || signal.contains("unsafe");

        if (isHiddenInstruction) {
            markBlocked(scan, "Hard tampering rule fired: hidden instruction was found and the build remains blocked.",
                    "Hidden instruction detected in the review context; the scan still failed safely.",
                    "Prompt injection attempt was ignored but still detected",
                    "src/session.js", 22,
                    "A review note tried to override the security agent and force a safe result. The scan recognised the tampering attempt and kept the gate closed.",
                    "Detection rule: \"prompt injection should be treated as data, never instructions\"",
                    "Remove hidden instructions from comments, PR descriptions, and generated artifacts before review. Keep the review loop grounded in repo content only.",
                    "CWE-93");
            return;
        }

        if (isVulnerable) {
            markBlocked(scan, "The generated rule fired. Confirmed finding: data exposure in the auth flow.",
                    "The security gate found a confirmed issue that blocks the merge.",
                    "Sensitive user data is written to logs",
                    "src/auth.js", 41,
                    "A password reset flow logs the raw user record and exposes personal data to anyone with log access.",
                    "Semgrep rule: \"logger.info(user)\" in auth paths is mapped to a data-leak issue.",
                    "Remove raw record logging and emit only a non-sensitive identifier or redacted metadata.",
                    "CWE-532");
            return;
        }

        scan.setStatus("passed");
        scan.setVerdict("PASS");
        scan.setSummary("No confirmed issues were found in the changed code path.");
        scan.getLog().add("Gate 1 checks passed and no confirmed findings remain.");
        scanRepository.save(scan);
    }

    private void markBlocked(Scan scan, String logEntry, String summary, String title, String file, Integer line,
                             String description, String proof, String fix, String cwe) {
        scan.setStatus("blocked");
        scan.setVerdict("BLOCKED");
        scan.setSummary(summary);
        scan.getLog().add(logEntry);

        Finding finding = new Finding();
        finding.setTitle(title);
        finding.setSeverity("HIGH");
        finding.setFile(file);
        finding.setLine(line);
        finding.setDescription(description);
        finding.setProof(proof);
        finding.setFix(fix);
        finding.setCwe(cwe);
        scan.addFinding(finding);
        scanRepository.save(scan);
    }
}
