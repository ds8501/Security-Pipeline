package com.security.pipeline.service;

import com.security.pipeline.ai.ClaudeClient;
import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import com.security.pipeline.store.ScanStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class ScanService {
    private final ScanStore scanStore;
    private final GitService gitService;
    private final IntegrityService integrityService;
    private final ReviewService reviewService;
    private final ProofService proofService;
    private final ClaudeClient claudeClient;
    private final ExecutorService reviewExecutor = Executors.newFixedThreadPool(Math.max(2, Runtime.getRuntime().availableProcessors()));
    private final ConcurrentHashMap<Long, AtomicBoolean> cancellationFlags = new ConcurrentHashMap<>();

    public ScanService(ScanStore scanStore) {
        this(scanStore, null, null, null, null, new ClaudeClient());
    }

    @Autowired
    public ScanService(ScanStore scanStore, GitService gitService, IntegrityService integrityService,
                       ReviewService reviewService, ProofService proofService, ClaudeClient claudeClient) {
        this.scanStore = scanStore;
        this.gitService = gitService;
        this.integrityService = integrityService;
        this.reviewService = reviewService;
        this.proofService = proofService;
        this.claudeClient = claudeClient;
    }

    public List<Scan> getScans() {
        return scanStore.findAllByCreatedAtDesc();
    }

    public Scan getScan(Long id) {
        return scanStore.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + id));
    }

    public Scan createScan(String repoUrl, String branch) {
        return createScan(repoUrl, branch, "main");
    }

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

        Scan savedScan = scanStore.save(scan);
        cancellationFlags.put(savedScan.getId(), new AtomicBoolean(false));

        reviewExecutor.submit(() -> runReview(savedScan.getId(), normalizedBaseBranch));
        return savedScan;
    }

    public Scan cancelScan(Long scanId) {
        Scan scan = getScan(scanId);

        AtomicBoolean flag = cancellationFlags.get(scanId);
        if (flag != null) {
            flag.set(true);
        }

        if (!"passed".equalsIgnoreCase(scan.getStatus()) && !"blocked".equalsIgnoreCase(scan.getStatus())
                && !"error".equalsIgnoreCase(scan.getStatus()) && !"cancelled".equalsIgnoreCase(scan.getStatus())) {
            markCancelled(scan);
        }

        return scan;
    }

    // The scan is a live object in the store; mutations here are visible to pollers immediately.
    public void runReview(Long scanId, String baseBranch) {
        Scan scan = getScan(scanId);

        Path repoDir = null;
        try {
            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            scan.setStatus("running");
            scan.setVerdict("PENDING");
            scan.setSummary("Running Gate 2 review pipeline...");
            appendCheck(scan, "Fetch diff", "PENDING", "Waiting to start");
            appendCheck(scan, "Injection check", "PENDING", "Waiting for diff");
            appendCheck(scan, "AI review", "PENDING", "Waiting for diff");
            appendCheck(scan, "Semgrep proof", "PENDING", "Waiting for findings");
            appendCheck(scan, "Verdict", "PENDING", "Waiting for checks");

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            if (claudeClient == null || !claudeClient.isConfigured()) {
                appendCheck(scan, "Fetch diff", "FAIL", "LLM API key not configured");
                appendCheck(scan, "Injection check", "FAIL", "LLM API key not configured");
                appendCheck(scan, "AI review", "FAIL", "LLM API key not configured");
                appendCheck(scan, "Semgrep proof", "FAIL", "LLM API key not configured");
                appendCheck(scan, "Verdict", "FAIL", "LLM API key not configured");
                scan.setStatus("error");
                scan.setVerdict("ERROR");
                scan.setSummary("LLM API key is not configured. Set LLM_API_KEY environment variable to enable the Gate-2 review pipeline.");
                scan.getLog().add("ERROR: LLM API key is not configured. Set LLM_API_KEY environment variable.");
                return;
            }

            scan.getLog().add("Fetching diff for " + baseBranch + "..." + scan.getBranch());

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            DiffContext diffContext = gitService.fetchDiff(scan.getRepoUrl(), scan.getBranch(), baseBranch);
            repoDir = diffContext.repoDir();
            appendCheck(scan, "Fetch diff", "PASS", "Loaded " + diffContext.changedFiles().size() + " changed file(s)");
            scan.getLog().add("Fetched diff with " + diffContext.changedFiles().size() + " changed file(s).");

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            IntegrityService.InjectionResult injectionResult = integrityService.detectInjection(diffContext.rawDiff());
            if (injectionResult.detected()) {
                appendCheck(scan, "Injection check", "FAIL", injectionResult.evidence());
            } else {
                appendCheck(scan, "Injection check", "PASS", "No prompt injection detected");
            }
            scan.getLog().add("Integrity check: injection=" + injectionResult.detected() + " | " + injectionResult.evidence());

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            List<Finding> reviewFindings = new ArrayList<>(reviewService.review(diffContext));
            int reviewCount = reviewFindings.size();
            scan.setFindings(reviewFindings);
            appendCheck(scan, "AI review", "PASS", "Generated " + reviewCount + " potential finding(s)");
            scan.getLog().add("AI review generated " + reviewCount + " potential finding(s).");

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            // Cap findings at 3 to respect free tier rate limits (10 req/min).
            List<Finding> findings = scan.getFindings();
            List<Finding> cappedFindings = findings;
            if (findings.size() > 3) {
                cappedFindings = new ArrayList<>(findings.subList(0, 3));
                scan.getLog().add("Capping findings at 3 to stay within free tier rate limits. Found " + findings.size() + " total.");
            }

            proofService.proveAll(scan, cappedFindings, repoDir);
            if (cappedFindings.isEmpty()) {
                appendCheck(scan, "Semgrep proof", "PASS", "No findings to prove");
            } else {
                long confirmed = cappedFindings.stream().filter(f -> "CONFIRMED".equalsIgnoreCase(f.getProofStatus())).count();
                appendCheck(scan, "Semgrep proof", confirmed > 0 ? "PASS" : "PENDING", "Verified " + confirmed + " confirmed finding(s)");
            }
            scan.getLog().add("Proof layer completed for " + cappedFindings.size() + " finding(s).");

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            boolean suspiciousClean = integrityService.suspiciousCleanVerdict(diffContext.changedFiles(), reviewCount);
            decideVerdict(scan, injectionResult.detected(), suspiciousClean);
            if ("BLOCKED".equals(scan.getVerdict())) {
                appendCheck(scan, "Verdict", "FAIL", scan.getSummary());
            } else {
                appendCheck(scan, "Verdict", "PASS", scan.getSummary());
            }
            scan.getLog().add("Final verdict: " + scan.getVerdict() + " - " + scan.getSummary());
        } catch (Exception e) {
            appendCheck(scan, "Verdict", "FAIL", e.getMessage());
            scan.setStatus("error");
            scan.setVerdict("ERROR");
            scan.setSummary("Review pipeline failed: " + e.getMessage());
            scan.getLog().add("ERROR: " + e.getMessage());
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

    private void appendCheck(Scan scan, String name, String status, String details) {
        String prefix = status == null ? "PENDING" : status.toUpperCase();
        String entry = name + ": " + prefix + (details == null || details.isBlank() ? "" : " - " + details);
        scan.getLog().add(entry);
    }

    private boolean isCancelled(Long scanId) {
        AtomicBoolean flag = cancellationFlags.get(scanId);
        return flag != null && flag.get();
    }

    private void markCancelled(Scan scan) {
        scan.setStatus("cancelled");
        scan.setVerdict("CANCELLED");
        scan.setSummary("Scan stopped by the user.");
        scan.getLog().add("Scan cancelled by user.");
    }
}
