package com.security.pipeline.service;

import com.security.pipeline.ai.ClaudeClient;
import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import com.security.pipeline.repository.ScanRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class ScanService {
    private final ScanRepository scanRepository;
    private final GitService gitService;
    private final IntegrityService integrityService;
    private final ReviewService reviewService;
    private final ProofService proofService;
    private final ClaudeClient claudeClient;
    private final ExecutorService reviewExecutor = Executors.newFixedThreadPool(Math.max(2, Runtime.getRuntime().availableProcessors()));

    public ScanService(ScanRepository scanRepository) {
        this(scanRepository, null, null, null, null, new ClaudeClient());
    }

    @Autowired
    public ScanService(ScanRepository scanRepository, GitService gitService, IntegrityService integrityService,
                      ReviewService reviewService, ProofService proofService, ClaudeClient claudeClient) {
        this.scanRepository = scanRepository;
        this.gitService = gitService;
        this.integrityService = integrityService;
        this.reviewService = reviewService;
        this.proofService = proofService;
        this.claudeClient = claudeClient;
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
        return createScan(repoUrl, branch, "main");
    }

    @Transactional
    public Scan createScan(String repoUrl, String branch, String baseBranch) {
        String normalizedRepo = repoUrl == null ? "" : repoUrl.trim();
        String normalizedBranch = branch == null ? "" : branch.trim();
        String normalizedBaseBranch = baseBranch == null || baseBranch.isBlank() ? "main" : baseBranch.trim();

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

        reviewExecutor.submit(() -> runReview(scan.getId(), normalizedBaseBranch));
        return scanRepository.findById(scan.getId()).orElse(scan);
    }

    @Transactional
    public void runReview(Long scanId, String baseBranch) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + scanId));

        Path repoDir = null;
        try {
            if (claudeClient == null || !claudeClient.isConfigured()) {
                scan.setStatus("error");
                scan.setVerdict("ERROR");
                scan.setSummary("Anthropic API key is not configured. Set ANTHROPIC_API_KEY to enable the gate-2 review pipeline.");
                scan.getLog().add("ERROR: Anthropic API key is not configured.");
                scanRepository.save(scan);
                return;
            }

            scan.setStatus("running");
            scan.setVerdict("PENDING");
            scan.setSummary("Fetching repository diff...");
            scan.getLog().add("Fetching diff for " + baseBranch + "..." + scan.getBranch());
            scanRepository.save(scan);

            DiffContext diffContext = gitService.fetchDiff(scan.getRepoUrl(), scan.getBranch(), baseBranch);
            repoDir = diffContext.repoDir();
            scan.getLog().add("Fetched diff with " + diffContext.changedFiles().size() + " changed file(s).");
            scanRepository.save(scan);

            IntegrityService.InjectionResult injectionResult = integrityService.detectInjection(diffContext.rawDiff());
            scan.getLog().add("Integrity check: injection=" + injectionResult.detected() + " | " + injectionResult.evidence());
            scanRepository.save(scan);

            List<Finding> findings = new ArrayList<>(reviewService.review(diffContext));
            scan.getFindings().clear();
            for (Finding finding : findings) {
                scan.addFinding(finding);
            }
            scan.getLog().add("AI review generated " + findings.size() + " potential finding(s).");
            scanRepository.save(scan);

            proofService.proveAll(scan, findings, repoDir);
            scan.getLog().add("Proof layer completed for " + findings.size() + " finding(s).");
            scanRepository.save(scan);

            boolean suspiciousClean = integrityService.suspiciousCleanVerdict(diffContext.changedFiles(), findings.size());
            decideVerdict(scan, injectionResult.detected(), suspiciousClean);
            scan.getLog().add("Final verdict: " + scan.getVerdict() + " - " + scan.getSummary());
            scanRepository.save(scan);
        } catch (Exception e) {
            scan.setStatus("error");
            scan.setVerdict("ERROR");
            scan.setSummary("Review pipeline failed: " + e.getMessage());
            scan.getLog().add("ERROR: " + e.getMessage());
            scanRepository.save(scan);
        } finally {
            if (gitService != null && repoDir != null) {
                gitService.cleanup(repoDir);
            }
        }
    }

    void decideVerdict(Scan scan, boolean injectionDetected, boolean suspiciousClean) {
        List<Finding> findings = scan.getFindings() == null ? List.of() : scan.getFindings();
        int confirmed = 0;
        int unproven = 0;
        boolean confirmedHighOrCritical = false;

        for (Finding finding : findings) {
            if ("CONFIRMED".equalsIgnoreCase(finding.getProofStatus())) {
                confirmed++;
                if ("HIGH".equalsIgnoreCase(finding.getSeverity()) || "CRITICAL".equalsIgnoreCase(finding.getSeverity())) {
                    confirmedHighOrCritical = true;
                }
            } else {
                unproven++;
            }
        }

        boolean blocked = injectionDetected || suspiciousClean || confirmedHighOrCritical;
        scan.setVerdict(blocked ? "BLOCKED" : "PASS");
        scan.setStatus(blocked ? "blocked" : "passed");
        scan.setSummary(confirmed + " confirmed, " + unproven + " unproven");
    }
}
