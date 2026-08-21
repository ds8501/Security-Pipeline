package com.security.pipeline.entity;

/**
 * A declared service in the attack-surface inventory.
 *   exposure = "public" (internet-facing → in scope for the red team) or "private" (internal).
 */
public class ServiceEntry {
    private String name;
    private String exposure = "private";
    private String url;

    public ServiceEntry() {
    }

    public ServiceEntry(String name, String exposure, String url) {
        this.name = name;
        this.exposure = exposure;
        this.url = url;
    }

    public boolean isPublic() {
        return "public".equalsIgnoreCase(exposure);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getExposure() {
        return exposure;
    }

    public void setExposure(String exposure) {
        this.exposure = exposure;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
