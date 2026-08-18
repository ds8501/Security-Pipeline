package com.security.pipeline.entity;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** In-memory Gate-1 run record: either a dispatched GitHub Actions run or a local tool run. */
public class Gate1Run {
    private Long id;
    private String mode;                 // github | local
    private String ref;                  // branch/ref scanned
    private String repoUrl;              // used by local mode
    private LocalDateTime createdAt = LocalDateTime.now();
    private volatile String status = "queued";   // queued | running | completed | error
    private volatile String conclusion = "PENDING"; // PASS | BLOCKED | ERROR | PENDING
    private volatile String summary = "Waiting to start.";
    private volatile String runUrl;      // GitHub Actions run URL (github mode)
    private final List<String> log = new CopyOnWriteArrayList<>();
    private final List<Gate1Check> checks = new CopyOnWriteArrayList<>();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getRef() {
        return ref;
    }

    public void setRef(String ref) {
        this.ref = ref;
    }

    public String getRepoUrl() {
        return repoUrl;
    }

    public void setRepoUrl(String repoUrl) {
        this.repoUrl = repoUrl;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getConclusion() {
        return conclusion;
    }

    public void setConclusion(String conclusion) {
        this.conclusion = conclusion;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getRunUrl() {
        return runUrl;
    }

    public void setRunUrl(String runUrl) {
        this.runUrl = runUrl;
    }

    public List<String> getLog() {
        return log;
    }

    public List<Gate1Check> getChecks() {
        return checks;
    }
}
