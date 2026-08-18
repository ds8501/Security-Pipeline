package com.security.pipeline.entity;

/** In-memory finding record produced by the AI review and annotated by the proof layer. */
public class Finding {
    private String title;
    private String severity;
    private String file;
    private Integer line;
    private String description;
    private String proof;
    private String fix;
    private String cwe;
    private String owasp;
    private String proofStatus = "UNPROVEN";

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getFile() {
        return file;
    }

    public void setFile(String file) {
        this.file = file;
    }

    public Integer getLine() {
        return line;
    }

    public void setLine(Integer line) {
        this.line = line;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getProof() {
        return proof;
    }

    public void setProof(String proof) {
        this.proof = proof;
    }

    public String getFix() {
        return fix;
    }

    public void setFix(String fix) {
        this.fix = fix;
    }

    public String getCwe() {
        return cwe;
    }

    public void setCwe(String cwe) {
        this.cwe = cwe;
    }

    public String getOwasp() {
        return owasp;
    }

    public void setOwasp(String owasp) {
        this.owasp = owasp;
    }

    public String getProofStatus() {
        return proofStatus;
    }

    public void setProofStatus(String proofStatus) {
        this.proofStatus = proofStatus;
    }
}
