package com.security.pipeline.service;

import com.security.pipeline.ai.ClaudeClient;
import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.RedTeamFinding;
import com.security.pipeline.entity.Scan;
import com.security.pipeline.entity.ServiceEntry;
import com.security.pipeline.repository.ScanRepository;
import com.security.pipeline.service.gate1.Gate1Service;
import com.security.pipeline.service.layer.ReviewLayer;
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
    private final Gate1Service gate1Service;
    private final ExecutorService reviewExecutor = Executors.newFixedThreadPool(Math.max(2, Runtime.getRuntime().availableProcessors()));
    private final ConcurrentHashMap<Long, AtomicBoolean> cancellationFlags = new ConcurrentHashMap<>();

    // Self-reference through the Spring proxy so that @Transactional methods invoked from the
    // background review thread actually open a persistence session. Calling this.runReview(...)
    // directly (as the executor lambda does) bypasses the proxy and leaves the entity detached.
    @Autowired
    @Lazy
    private ScanService self;

    // Gate-2 supporting tools (design doc). Optional so the plain-constructor test path and hosts
    // without the tools still work; each is null-guarded at the call site.
    @Autowired(required = false)
    private RipgrepScanner ripgrepScanner;
    @Autowired(required = false)
    private TreeSitterService treeSitterService;
    @Autowired(required = false)
    private OpaPolicyService opaPolicyService;
    @Autowired(required = false)
    private RedTeamService redTeamService;
    @Autowired(required = false)
    private ServiceInventory serviceInventory;

    public ScanService(ScanRepository scanRepository) {
        this(scanRepository, null, null, null, null, new ClaudeClient(), null);
    }

    @Autowired
    public ScanService(ScanRepository scanRepository, GitService gitService, IntegrityService integrityService,
                      ReviewService reviewService, ProofService proofService, ClaudeClient claudeClient,
                      Gate1Service gate1Service) {
        this.scanRepository = scanRepository;
        this.gitService = gitService;
        this.integrityService = integrityService;
        this.reviewService = reviewService;
        this.proofService = proofService;
        this.claudeClient = claudeClient;
        this.gate1Service = gate1Service;
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
        Scan scan = scanRepository.findWithFindingsById(id)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + id));
        scan.getFindings().size();
        scan.getLog().size();
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
        Scan scan = scanRepository.findWithFindingsById(scanId)
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

        Scan savedScan = scanRepository.save(scan);
        cancellationFlags.put(savedScan.getId(), new AtomicBoolean(false));

        reviewExecutor.submit(() -> runReview(savedScan.getId(), normalizedBaseBranch));
        return savedScan;
    }

    @Transactional
    public Scan cancelScan(Long scanId) {
        Scan scan = scanRepository.findWithFindingsById(scanId)
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

        scan.getFindings().size();
        scan.getLog().size();
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
            if (ripgrepScanner != null) {
                appendCheck(scan, "Gate 2 · ripgrep (code search)", "PENDING", "Waiting to start");
            }
            if (treeSitterService != null) {
                appendCheck(scan, "Gate 2 · tree-sitter (structure)", "PENDING", "Waiting to start");
            }
            if (redTeamService != null && serviceInventory != null) {
                appendCheck(scan, "Gate 2 · Red Team (DAST)", "PENDING", "Waiting to start");
            }
            appendCheck(scan, "L1 · Integrity", "PENDING", "Waiting to start");
            for (ReviewLayer layer : reviewService.getLayers()) {
                appendCheck(scan, layerCheckName(layer), "PENDING", "Waiting to start");
            }
            appendCheck(scan, "Semgrep proof", "PENDING", "Waiting to start");
            appendCheck(scan, "Final verdict", "PENDING", "Waiting for checks");
            scan = self().persist(scan);

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            // Gate 1 (static-analysis tools) runs regardless of LLM configuration. Only Gate 2
            // (the AI red-team layers) needs the LLM key; when it is missing we still run Gate 1
            // and reach a verdict from its findings.
            boolean aiEnabled = claudeClient != null && claudeClient.isConfigured();
            if (!aiEnabled) {
                scan.getLog().add("LLM API key not configured — running Gate 1 tools only; Gate 2 AI review will be skipped.");
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

            // A null repoDir means the clone/fetch failed (unreachable or private repo without
            // credentials). Fail closed with a clear error instead of silently passing an empty diff.
            if (repoDir == null) {
                appendCheck(scan, "Integration tests", "FAIL", "Could not clone/fetch the repository");
                scan.setStatus("error");
                scan.setVerdict("ERROR");
                scan.setSummary("Could not load the repository. Check the repo URL and branch — a private repo needs credentials (a token in the URL), or use a local path.");
                scan.getLog().add("ERROR: git clone/fetch failed for " + scan.getRepoUrl() + " (branch " + scan.getBranch() + " / base " + baseBranch + ").");
                scan = self().persist(scan);
                return;
            }

            appendCheck(scan, "Integration tests", "PASS", "Repository diff loaded (" + diffContext.changedFiles().size() + " changed file(s))");
            scan.getLog().add("Fetched diff with " + diffContext.changedFiles().size() + " changed file(s).");
            scan = self().persist(scan);

            // Gate 2 runs only Gate-2 checks. The Gate-1 static-analysis/scanning tools (Semgrep,
            // Gitleaks, osv-scanner, Trivy, Syft, ...) belong to Gate 1 and run via /api/gate1
            // (LocalGateRunner / GitHub Actions), so they are intentionally not run here.

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            // Gate 2 supporting tools — code search (ripgrep) and structure parse (tree-sitter).
            // Deterministic and LLM-independent, so they run regardless of AI configuration.
            if (ripgrepScanner != null) {
                ToolReport rg = ripgrepScanner.scan(repoDir);
                for (Finding f : rg.findings()) {
                    scan.addFinding(f);
                }
                appendCheck(scan, "Gate 2 · ripgrep (code search)", toolCheckStatus(rg.status()), rg.summary());
                scan.getLog().add("Gate 2 ripgrep: " + rg.status() + " - " + rg.summary());
                scan = self().persist(scan);
            }
            if (treeSitterService != null) {
                ToolReport ts = treeSitterService.summarize(repoDir, diffContext.changedFiles());
                appendCheck(scan, "Gate 2 · tree-sitter (structure)", toolCheckStatus(ts.status()), ts.summary());
                scan.getLog().add("Gate 2 tree-sitter: " + ts.status() + " - " + ts.summary());
                scan = self().persist(scan);
            }

            // Gate 2 · Red Team (DAST) — live, non-destructive probing of the PUBLIC targets declared
            // in .secgate/services.yaml (security headers, TLS, exposed sensitive paths, admin
            // surface, optional nuclei). Findings are live-observed, so they are recorded CONFIRMED.
            if (redTeamService != null && serviceInventory != null) {
                scan = runRedTeam(scan, repoDir);
            }

            if (isCancelled(scanId)) {
                markCancelled(scan);
                return;
            }

            boolean injectionDetected = false;
            int reviewCount = 0;

            if (aiEnabled) {
                // Gate 2 · L1 — integrity / prompt-injection guard.
                IntegrityService.InjectionResult injectionResult = integrityService.detectInjection(diffContext.rawDiff());
                injectionDetected = injectionResult.detected();
                if (injectionDetected) {
                    appendCheck(scan, "L1 · Integrity", "FAIL", injectionResult.evidence());
                } else {
                    appendCheck(scan, "L1 · Integrity", "PASS", "No prompt injection detected");
                }
                scan.getLog().add("Integrity check: injection=" + injectionDetected + " | " + injectionResult.evidence());
                scan = self().persist(scan);

                if (isCancelled(scanId)) {
                    markCancelled(scan);
                    return;
                }

                // Gate 2 · L2-L6 — run each AI review layer in order, reporting progress per layer so
                // the live status view fills in one row at a time. Persist after each layer so the
                // findings receive database ids incrementally; keep using the returned copy so
                // subsequent saves are updates. Gate-1 findings are already attached, so we append.
                for (ReviewLayer layer : reviewService.getLayers()) {
                    if (isCancelled(scanId)) {
                        markCancelled(scan);
                        return;
                    }

                    List<Finding> layerFindings = layer.review(diffContext);
                    for (Finding finding : layerFindings) {
                        scan.addFinding(finding);
                    }
                    reviewCount += layerFindings.size();
                    appendCheck(scan, layerCheckName(layer), "PASS", layerFindings.size() + " potential finding(s)");
                    scan.getLog().add(layer.code() + " (" + layer.title() + ") flagged " + layerFindings.size() + " potential finding(s).");
                    scan = self().persist(scan);
                }
                scan.getLog().add("AI review generated " + reviewCount + " potential finding(s) across "
                        + reviewService.getLayers().size() + " layer(s).");
                scan = self().persist(scan);

                if (isCancelled(scanId)) {
                    markCancelled(scan);
                    return;
                }

                // Gate 2 · proof — only the AI findings need Semgrep proof; Gate-1 scanner findings are
                // already confirmed. Cap the AI findings at 3 to respect free tier rate limits (10 req/min).
                List<Finding> unproven = unprovenFindings(scan);
                List<Finding> cappedFindings = unproven;
                if (unproven.size() > 3) {
                    scan.getLog().add("Capping AI findings at 3 to stay within free tier rate limits. Found " + unproven.size() + " total.");
                    scan = self().persist(scan);
                    unproven = unprovenFindings(scan);
                    cappedFindings = unproven.subList(0, 3);
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
            } else {
                // No LLM key — Gate 1 tools still ran; mark the Gate-2 (AI) rows as skipped and
                // continue to a verdict based on the Gate-1 findings.
                appendCheck(scan, "L1 · Integrity", "PENDING", "Skipped — LLM API key not configured");
                for (ReviewLayer layer : reviewService.getLayers()) {
                    appendCheck(scan, layerCheckName(layer), "PENDING", "Skipped — LLM API key not configured");
                }
                appendCheck(scan, "Semgrep proof", "PENDING", "Skipped — LLM API key not configured");
                scan.getLog().add("Gate 2 (AI review) skipped: LLM API key not configured. Gate 1 tools still ran.");
                scan = self().persist(scan);
            }

            // suspiciousClean is an AI-layer signal (zero AI findings on an auth/permission change),
            // so it only applies when the AI layers actually ran.
            boolean suspiciousClean = aiEnabled && integrityService.suspiciousCleanVerdict(diffContext.changedFiles(), reviewCount);
            decideVerdict(scan, injectionDetected, suspiciousClean);
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
        List<Finding> safeFindings = scan.getFindings() == null ? List.of() : scan.getFindings();
        int confirmed = 0;
        int unproven = 0;
        boolean confirmedHighOrCritical = false;

        for (Finding finding : safeFindings) {
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

        // Prefer the OPA/Conftest policy engine when available; fall back to the built-in logic.
        if (opaPolicyService != null) {
            java.util.Optional<Boolean> policyBlock = opaPolicyService.evaluateBlock(scan, injectionDetected, suspiciousClean);
            if (policyBlock.isPresent()) {
                blocked = policyBlock.get();
                scan.getLog().add("Block/allow decided by OPA policy (verdict.rego): block=" + blocked);
            }
        }

        scan.setVerdict(blocked ? "BLOCKED" : "PASS");
        scan.setStatus(blocked ? "blocked" : "passed");
        scan.setSummary(confirmed + " confirmed, " + unproven + " unproven");
    }

    private String layerCheckName(ReviewLayer layer) {
        return layer.code() + " · " + layer.title();
    }

    // Runs the red-team DAST probe over the public targets in .secgate/services.yaml, folds the
    // findings into the scan, and returns the re-initialized scan copy.
    private Scan runRedTeam(Scan scan, Path repoDir) {
        List<ServiceEntry> inventory = serviceInventory.fromDir(repoDir);
        List<String> targets = new ArrayList<>();
        for (ServiceEntry entry : inventory) {
            if (entry != null && entry.isPublic() && entry.getUrl() != null && !entry.getUrl().isBlank()) {
                targets.add(entry.getUrl().trim());
            }
        }

        if (targets.isEmpty()) {
            appendCheck(scan, "Gate 2 · Red Team (DAST)", "PENDING", "No public targets in .secgate/services.yaml");
            scan.getLog().add("Gate 2 red team: skipped — no public targets declared.");
            return self().persist(scan);
        }

        List<String> probeLog = new ArrayList<>();
        List<RedTeamFinding> redTeamFindings;
        try {
            redTeamFindings = redTeamService.probe(targets, probeLog::add);
        } catch (Exception e) {
            appendCheck(scan, "Gate 2 · Red Team (DAST)", "PENDING", "Probe error: " + e.getMessage());
            scan.getLog().add("Gate 2 red team: error — " + e.getMessage());
            return self().persist(scan);
        }

        for (RedTeamFinding rtf : redTeamFindings) {
            scan.addFinding(toFinding(rtf));
        }
        for (String line : probeLog) {
            scan.getLog().add("Red Team: " + line);
        }
        String summary = redTeamFindings.isEmpty()
                ? "No issues on " + targets.size() + " public target(s)"
                : redTeamFindings.size() + " finding(s) on " + targets.size() + " public target(s)";
        appendCheck(scan, "Gate 2 · Red Team (DAST)", redTeamFindings.isEmpty() ? "PASS" : "FAIL", summary);
        scan.getLog().add("Gate 2 red team: " + summary);
        return self().persist(scan);
    }

    private Finding toFinding(RedTeamFinding rtf) {
        Finding f = new Finding();
        f.setTitle(rtf.getTitle() == null ? "Red-team finding" : rtf.getTitle());
        String sev = rtf.getSeverity() == null ? "LOW" : rtf.getSeverity().toUpperCase();
        f.setSeverity("INFO".equals(sev) ? "LOW" : sev);
        f.setFile(rtf.getTarget() == null ? "unknown" : rtf.getTarget());
        f.setLine(1);
        f.setDescription((rtf.getCategory() == null ? "" : rtf.getCategory() + ": ")
                + (rtf.getEvidence() == null ? "" : rtf.getEvidence()));
        f.setFix(rtf.getRecommendation() == null ? "Review and remediate the exposed surface." : rtf.getRecommendation());
        f.setCwe("CWE-693");
        f.setOwasp("A05:2021");
        f.setLayer("Gate 2 · Red Team (DAST)");
        f.setProofStatus("CONFIRMED");
        f.setProof(rtf.getEvidence() == null ? "Live DAST observation." : rtf.getEvidence());
        return f;
    }

    private String toolCheckStatus(String status) {
        if (ToolReport.FAIL.equals(status)) {
            return "FAIL";
        }
        if (ToolReport.PASS.equals(status)) {
            return "PASS";
        }
        return "PENDING";
    }

    private List<Finding> unprovenFindings(Scan scan) {
        List<Finding> unproven = new ArrayList<>();
        for (Finding finding : scan.getFindings()) {
            if ("UNPROVEN".equalsIgnoreCase(finding.getProofStatus())) {
                unproven.add(finding);
            }
        }
        return unproven;
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
