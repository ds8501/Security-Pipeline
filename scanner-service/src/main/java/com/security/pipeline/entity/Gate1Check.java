package com.security.pipeline.entity;

/** One Gate-1 check row (a workflow job in GitHub mode, or a tool run in local mode). */
public class Gate1Check {
    private String name;
    private volatile String status = "queued";       // queued | running | completed | skipped
    private volatile String conclusion;               // success | failure | neutral | skipped | null
    private volatile String details = "";
    private volatile String url;                      // link to the job / logs, when available

    public Gate1Check() {
    }

    public Gate1Check(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
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

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
