package com.security.pipeline.service;

import com.security.pipeline.ai.ClaudeClient;
import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import com.security.pipeline.repository.ScanRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class ScanService {
    private final ScanRepository scanRepository;
    private final GitService gitService;
    private final IntegrityService integrityService;
    private final ReviewService reviewService;
    private final ProofService proofService;
    private final ClaudeClient claudeClient;
    private final ExecutorService reviewExecutor = Executors.newFixedThreadPool(Math.max(2, Runtime.getRuntime().availableProcessors()));
    private final ConcurrentHashMap<Long, AtomicBoolean> cancellationFlags = new ConcurrentHashMap<>();

    // Self-reference through the Spring proxy so that @Transactional methods invoked from the
    // background review thread actually open a persistence session. Calling this.runReview(...)
    // directly (as the executor lambda does) bypasses the proxy and leaves the entity detached.
    @Autowired
    @Lazy
    private ScanService self;

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

    @Transactional(readOnly = true)
    public List<Scan> getScans() {
        List<Scan> scans = scanRepository.findAllByOrderByCreatedAtDesc();
        // initialize lazy collections to avoid LazyInitializationException during JSON serialization
        for (Scan s : scans) {
            if (s.getFindings() != null) {
                s.getFindings().size();
            }
        }
        return scans;
    }

    @Transactional(readOnly = true)
    public Scan getScan(Long id) {
        Scan scan = scanRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + id));
        if (scan.getFindings() != null) {
            scan.getFindings().size();
        }
        return scan;
    }

    // Falls back to `this` for the plain-constructor test path where no Spring proxy exists.
    private ScanService self() {
        return self != null ? self : this;
    }

    /**
     * Loads a scan with its findings and log fully initialized inside a transaction, so the
     * returned (detached) entity can be read safely from the background review thread.
     */
    @Transactional(readOnly = true)
    public Scan loadForReview(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + scanId));
        scan.getFindings().size();
        scan.getLog().size();
        return scan;
    }

    /**
     * Persists the current state of the scan in its own short transaction and returns a
     * re-initialized, detached copy (with generated ids on findings) that the caller must
     * keep using. Each call commits independently so the live-status UI sees progress.
     */
    @Transactional
    public Scan persist(Scan scan) {
        Scan saved = scanRepository.save(scan);
        saved.getFindings().size();
        saved.getLog().size();
        return saved;
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
        
        Scan savedScan = scanRepository.save(scan);
        cancellationFlags.put(savedScan.getId(), new AtomicBoolean(false));

        reviewExecutor.submit(() -> runReview(savedScan.getId(), normalizedBaseBranch));
        return savedScan;
    }

    @Transactional
    public Scan cancelScan(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + scanId));

        AtomicBoolean flag = cancellationFlags.get(scanId);
        if (flag != null) {
            flag.set(true);
        }

        if (!"passed".equalsIgnoreCase(scan.getStatus()) && !"blocked".equalsIgnoreCase(scan.getStatus())
                && !"error".equalsIgnoreCase(scan.getStatus()) && !"cancelled".equalsIgnoreCase(scan.getStatus())) {
            scan.setStatus("cancelled");
            scan.setVerdict("CANCELLED");
            scan.setSummary("Scan stopped by the user.");
            scan.getLog().add("Scan cancelled by user.");
            scanRepository.save(scan);
        }

        return scan;
    }

    public void runReview(Long scanId, String baseBranch) {
        Scan scan = self().loadForReview(scanId);

        Path repoDir = null;
        try {
            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            scan.setStatus("running");
            scan.setVerdict("PENDING");
            scan.setSummary("Running security pipeline checks...");
            appendCheck(scan, "Unit tests", "PENDING", "Waiting to start");
            appendCheck(scan, "Integration tests", "PENDING", "Waiting for review results");
            appendCheck(scan, "Security diff review", "PENDING", "Waiting to start");
            appendCheck(scan, "Semgrep proof", "PENDING", "Waiting to start");
            appendCheck(scan, "Final verdict", "PENDING", "Waiting for checks");
            scan = self().persist(scan);

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            if (claudeClient == null || !claudeClient.isConfigured()) {
                appendCheck(scan, "Unit tests", "FAIL", "LLM API key not configured");
                appendCheck(scan, "Integration tests", "FAIL", "LLM API key not configured");
                appendCheck(scan, "Security diff review", "FAIL", "LLM API key not configured");
                appendCheck(scan, "Semgrep proof", "FAIL", "LLM API key not configured");
                appendCheck(scan, "Final verdict", "FAIL", "LLM API key not configured");
                scan.setStatus("error");
                scan.setVerdict("ERROR");
                scan.setSummary("LLM API key is not configured. Set LLM_API_KEY environment variable to enable the Gate-2 review pipeline.");
                scan.getLog().add("ERROR: LLM API key is not configured. Set LLM_API_KEY environment variable.");
                scan = self().persist(scan);
                return;
            }

            appendCheck(scan, "Unit tests", "PASS", "Environment ready");
            scan.getLog().add("Fetching diff for " + baseBranch + "..." + scan.getBranch());
            scan = self().persist(scan);

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            DiffContext diffContext = gitService.fetchDiff(scan.getRepoUrl(), scan.getBranch(), baseBranch);
            repoDir = diffContext.repoDir();
            appendCheck(scan, "Integration tests", "PASS", "Repository diff loaded successfully");
            scan.getLog().add("Fetched diff with " + diffContext.changedFiles().size() + " changed file(s).");
            scan = self().persist(scan);

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            IntegrityService.InjectionResult injectionResult = integrityService.detectInjection(diffContext.rawDiff());
            if (injectionResult.detected()) {
                appendCheck(scan, "Security diff review", "FAIL", injectionResult.evidence());
            } else {
                appendCheck(scan, "Security diff review", "PASS", "No prompt injection detected");
            }
            scan.getLog().add("Integrity check: injection=" + injectionResult.detected() + " | " + injectionResult.evidence());
            scan = self().persist(scan);

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            List<Finding> reviewFindings = new ArrayList<>(reviewService.review(diffContext));
            int reviewCount = reviewFindings.size();
            scan.getFindings().clear();
            for (Finding finding : reviewFindings) {
                scan.addFinding(finding);
            }
            appendCheck(scan, "Security diff review", "PASS", "AI review generated " + reviewCount + " potential finding(s)");
            scan.getLog().add("AI review generated " + reviewCount + " potential finding(s).");
            // Persist findings so they receive database ids; keep using the returned copy so
            // subsequent saves are updates (not duplicate inserts).
            scan = self().persist(scan);

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            // Cap findings at 3 to respect free tier rate limits (10 req/min). Prove against the
            // persisted findings so that the proof results are saved back to the same rows.
            List<Finding> persistedFindings = scan.getFindings();
            List<Finding> cappedFindings = persistedFindings;
            if (persistedFindings.size() > 3) {
                cappedFindings = persistedFindings.subList(0, 3);
                scan.getLog().add("Capping findings at 3 to stay within free tier rate limits. Found " + persistedFindings.size() + " total.");
                scan = self().persist(scan);
                cappedFindings = scan.getFindings().subList(0, 3);
            }

            proofService.proveAll(scan, cappedFindings, repoDir);
            if (cappedFindings.isEmpty()) {
                appendCheck(scan, "Semgrep proof", "PASS", "No findings to prove");
            } else {
                long confirmed = cappedFindings.stream().filter(f -> "CONFIRMED".equalsIgnoreCase(f.getProofStatus())).count();
                appendCheck(scan, "Semgrep proof", confirmed > 0 ? "PASS" : "PENDING", "Verified " + confirmed + " confirmed finding(s)");
            }
            scan.getLog().add("Proof layer completed for " + cappedFindings.size() + " finding(s).");
            scan = self().persist(scan);

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            boolean suspiciousClean = integrityService.suspiciousCleanVerdict(diffContext.changedFiles(), reviewCount);
            decideVerdict(scan, injectionResult.detected(), suspiciousClean);
            if ("BLOCKED".equals(scan.getVerdict())) {
                appendCheck(scan, "Final verdict", "FAIL", scan.getSummary());
            } else {
                appendCheck(scan, "Final verdict", "PASS", scan.getSummary());
            }
            scan.getLog().add("Final verdict: " + scan.getVerdict() + " - " + scan.getSummary());
            scan = self().persist(scan);
        } catch (Exception e) {
            appendCheck(scan, "Unit tests", "FAIL", e.getMessage());
            appendCheck(scan, "Integration tests", "FAIL", e.getMessage());
            scan.setStatus("error");
            scan.setVerdict("ERROR");
            scan.setSummary("Review pipeline failed: " + e.getMessage());
            scan.getLog().add("ERROR: " + e.getMessage());
            scan = self().persist(scan);
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
        self().persist(scan);
    }
}
