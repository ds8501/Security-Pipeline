package com.security.pipeline.entity;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory scan record. Not persisted — a background review thread mutates it while the UI
 * polls it, so {@code log} and {@code findings} are copy-on-write for safe concurrent reads.
 */
public class Scan {
    private Long id;
    private String repoUrl;
    private String branch;
    private LocalDateTime createdAt = LocalDateTime.now();
    private volatile String status = "queued";
    private volatile String verdict = "PENDING";
    private volatile String summary = "Waiting for the security review pipeline to start.";
    private final List<String> log = new CopyOnWriteArrayList<>();
    private List<Finding> findings = new CopyOnWriteArrayList<>();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRepoUrl() {
        return repoUrl;
    }

    public void setRepoUrl(String repoUrl) {
        this.repoUrl = repoUrl;
    }

    public String getBranch() {
        return branch;
    }

    public void setBranch(String branch) {
        this.branch = branch;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getVerdict() {
        return verdict;
    }

    public void setVerdict(String verdict) {
        this.verdict = verdict;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public List<String> getLog() {
        return log;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public void setFindings(List<Finding> findings) {
        this.findings = new CopyOnWriteArrayList<>(findings);
    }

    public void addFinding(Finding finding) {
        findings.add(finding);
    }
}
