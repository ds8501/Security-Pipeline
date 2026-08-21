package com.security.pipeline.controller;

import com.security.pipeline.entity.Finding;
import com.security.pipeline.entity.Scan;
import com.security.pipeline.service.AutoFixService;
import com.security.pipeline.service.DiffContext;
import com.security.pipeline.service.GitHubPrService;
import com.security.pipeline.service.GitService;
import com.security.pipeline.service.ScanService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One-click auto-remediation: generates fixes for a scan's confirmed findings and opens a PR
 * (when a GitHub token is configured), otherwise returns the patches for manual application.
 */
@RestController
public class AutoFixController {

    private final ScanService scanService;
    private final GitService gitService;
    private final AutoFixService autoFixService;
    private final GitHubPrService gitHubPrService;

    public AutoFixController(ScanService scanService, GitService gitService,
                            AutoFixService autoFixService, GitHubPrService gitHubPrService) {
        this.scanService = scanService;
        this.gitService = gitService;
        this.autoFixService = autoFixService;
        this.gitHubPrService = gitHubPrService;
    }

    @PostMapping("/api/scans/{id}/autofix-pr")
    public ResponseEntity<Map<String, Object>> autofixPr(@PathVariable Long id,
                                                         @RequestParam(defaultValue = "main") String base) {
        Map<String, Object> out = new LinkedHashMap<>();
        Scan scan;
        try {
            scan = scanService.getScan(id);
        } catch (Exception e) {
            return ResponseEntity.status(404).body(Map.of("error", "Scan not found: " + id));
        }

        // Fixes are generated for real, reportable findings (drop the pure-informational ones).
        List<Finding> targets = new ArrayList<>();
        for (Finding f : scan.getFindings()) {
            String sev = f.getSeverity() == null ? "" : f.getSeverity().toUpperCase();
            if (!"LOW".equals(sev) && !"INFO".equals(sev)) {
                targets.add(f);
            }
        }
        if (targets.isEmpty()) {
            out.put("created", false);
            out.put("message", "No medium+ findings to fix.");
            return ResponseEntity.ok(out);
        }

        // Re-fetch the branch's file contents (the vulnerable files are part of the diff).
        DiffContext ctx = gitService.fetchDiff(scan.getRepoUrl(), scan.getBranch(), base);
        if (ctx == null || ctx.repoDir() == null) {
            return ResponseEntity.badRequest().body(Map.of("error",
                    "Could not load the repository to generate fixes (private repo needs a token in the URL)."));
        }

        try {
            // Group findings by file, generate the full corrected content per file.
            Map<String, List<Finding>> byFile = new LinkedHashMap<>();
            for (Finding f : targets) {
                if (f.getFile() != null && ctx.fileContents().containsKey(f.getFile())) {
                    byFile.computeIfAbsent(f.getFile(), k -> new ArrayList<>()).add(f);
                }
            }

            Map<String, String> fixedFiles = new LinkedHashMap<>();
            for (Map.Entry<String, List<Finding>> e : byFile.entrySet()) {
                String original = ctx.fileContents().get(e.getKey());
                String fixed = autoFixService.generateFixedFile(e.getKey(), original, e.getValue());
                if (fixed != null) {
                    fixedFiles.put(e.getKey(), fixed);
                }
            }

            if (fixedFiles.isEmpty()) {
                out.put("created", false);
                out.put("message", "No file-level fixes could be generated (fixes may need manual review).");
                return ResponseEntity.ok(out);
            }

            String title = "Security auto-fix: remediate " + targets.size() + " finding(s) from scan #" + id;
            String body = buildBody(scan, targets);
            GitHubPrService.PrResult result = gitHubPrService.openPullRequest(scan.getRepoUrl(), base, fixedFiles, title, body);

            out.put("created", result.created());
            out.put("prUrl", result.url());
            out.put("branch", result.branch());
            out.put("message", result.message());
            out.put("filesFixed", new ArrayList<>(fixedFiles.keySet()));
            if (!result.created()) {
                // Fall back to returning the corrected files so the user can apply them manually.
                out.put("fixedFiles", fixedFiles);
            }
            return ResponseEntity.ok(out);
        } finally {
            gitService.cleanup(ctx.repoDir());
        }
    }

    private String buildBody(Scan scan, List<Finding> findings) {
        StringBuilder b = new StringBuilder();
        b.append("Automated security fix generated by the Security Pipeline for scan #")
                .append(scan.getId()).append(" (`").append(scan.getBranch()).append("`).\n\n")
                .append("Findings addressed:\n");
        for (Finding f : findings) {
            b.append("- **").append(f.getSeverity()).append("** ").append(f.getTitle())
                    .append(" — `").append(f.getFile()).append(":").append(f.getLine()).append("`\n");
        }
        b.append("\n> Review carefully before merging.");
        return b.toString();
    }
}
