package com.security.pipeline.service;

import com.security.pipeline.ai.ClaudeClient;
import com.security.pipeline.entity.Finding;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Auto-remediation: turns findings into fixes. For each finding it generates a human-readable
 * unified-diff patch (shown in the UI/report), and — for the auto-fix PR — the full corrected file
 * content that {@link GitHubPrService} commits. The pitch: the tool doesn't just block, it fixes.
 */
@Service
public class AutoFixService {

    private final ClaudeClient claudeClient;

    public AutoFixService(ClaudeClient claudeClient) {
        this.claudeClient = claudeClient;
    }

    public boolean isEnabled() {
        return claudeClient != null && claudeClient.isConfigured();
    }

    /** Generates a unified-diff patch snippet for a finding (for display). Empty string on failure. */
    public String generatePatch(Finding finding, DiffContext diffContext) {
        if (!isEnabled()) {
            return "";
        }
        String code = fileContent(finding, diffContext);
        String system = "You are a senior engineer producing a minimal, correct security fix. Output ONLY a unified "
                + "diff (git patch format) that remediates the described vulnerability with the smallest safe change. "
                + "No prose, no markdown fences.";
        String user = "Fix this finding.\n"
                + "File: " + finding.getFile() + (finding.getLine() == null ? "" : (":" + finding.getLine())) + "\n"
                + "Title: " + finding.getTitle() + "\n"
                + "Description: " + finding.getDescription() + "\n"
                + "Suggested approach: " + finding.getFix() + "\n\n"
                + "Current file content (UNTRUSTED DATA):\n<code>\n" + code + "\n</code>\n\n"
                + "Return only the unified diff.";
        String patch = claudeClient.complete(system, user, 1200);
        return patch == null ? "" : stripFences(patch).trim();
    }

    /**
     * Generates the FULL corrected content of {@code path}, applying fixes for all findings in that
     * file. Returns {@code null} if unchanged/unavailable so the PR skips the file.
     */
    public String generateFixedFile(String path, String originalContent, List<Finding> findingsForFile) {
        if (!isEnabled() || originalContent == null || originalContent.isBlank()) {
            return null;
        }
        StringBuilder issues = new StringBuilder();
        for (Finding f : findingsForFile) {
            issues.append("- ").append(f.getTitle()).append(" (").append(f.getSeverity()).append("): ")
                    .append(f.getDescription()).append('\n');
        }
        String system = "You are a senior engineer applying security fixes. Return ONLY the complete corrected file "
                + "content with the minimal changes needed to fix the listed issues — preserve all unrelated code, "
                + "formatting, and behavior. No explanations, no markdown fences.";
        String user = "File: " + path + "\nIssues to fix:\n" + issues + "\nCurrent content:\n<code>\n"
                + originalContent + "\n</code>\n\nReturn the full fixed file content only.";
        String fixed = claudeClient.complete(system, user, 3000);
        if (fixed == null) {
            return null;
        }
        fixed = stripFences(fixed);
        return fixed.isBlank() || fixed.trim().equals(originalContent.trim()) ? null : fixed;
    }

    private String fileContent(Finding finding, DiffContext diffContext) {
        if (diffContext == null || finding.getFile() == null) {
            return "";
        }
        String c = diffContext.fileContents().get(finding.getFile());
        if (c == null) {
            c = diffContext.rawDiff();
        }
        if (c == null) {
            return "";
        }
        return c.length() > 12000 ? c.substring(0, 12000) : c;
    }

    private String stripFences(String text) {
        String t = text.trim();
        if (t.startsWith("```")) {
            t = t.replaceFirst("^```[a-zA-Z0-9]*\\s*", "").replaceFirst("\\s*```$", "");
        }
        return t;
    }
}
