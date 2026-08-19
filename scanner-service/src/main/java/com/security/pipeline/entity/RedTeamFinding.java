package com.security.pipeline.entity;

/** One red-team finding produced by probing a live target. */
public class RedTeamFinding {
    private String title;
    private String severity;   // CRITICAL | HIGH | MEDIUM | LOW | INFO
    private String target;
    private String category;   // e.g. "Security headers", "Exposed path", "TLS", "nuclei"
    private String evidence;
    private String recommendation;

    public RedTeamFinding() {
    }

    public RedTeamFinding(String title, String severity, String target, String category, String evidence, String recommendation) {
        this.title = title;
        this.severity = severity;
        this.target = target;
        this.category = category;
        this.evidence = evidence;
        this.recommendation = recommendation;
    }

    public String getTitle() { return title; }
    public void setTitle(String v) { this.title = v; }
    public String getSeverity() { return severity; }
    public void setSeverity(String v) { this.severity = v; }
    public String getTarget() { return target; }
    public void setTarget(String v) { this.target = v; }
    public String getCategory() { return category; }
    public void setCategory(String v) { this.category = v; }
    public String getEvidence() { return evidence; }
    public void setEvidence(String v) { this.evidence = v; }
    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String v) { this.recommendation = v; }
}
