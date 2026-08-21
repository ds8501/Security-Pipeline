package com.security.pipeline.service;

import com.security.pipeline.entity.ServiceEntry;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Loads the attack-surface inventory from {@code .secgate/services.yaml} in the (already cloned)
 * repository. Only services marked {@code exposure: public} are in scope for the Gate 2 red-team.
 *
 * services.yaml:
 *   services:
 *     - name: web-api
 *       exposure: public
 *       url: https://api.example.com
 *     - name: internal-db
 *       exposure: private
 *       url: http://10.0.0.5:5432
 */
@Component
public class ServiceInventory {

    /** Read the inventory from a cloned repo directory (empty list if the file is absent). */
    public List<ServiceEntry> fromDir(Path repoDir) {
        try {
            if (repoDir == null) {
                return List.of();
            }
            Path yamlFile = repoDir.resolve(".secgate/services.yaml");
            if (!Files.exists(yamlFile)) {
                return List.of();
            }
            return parse(Files.readString(yamlFile, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return List.of();
        }
    }

    @SuppressWarnings("unchecked")
    List<ServiceEntry> parse(String yamlContent) {
        List<ServiceEntry> out = new ArrayList<>();
        try {
            Object root = new Yaml().load(yamlContent);
            if (!(root instanceof Map)) {
                return out;
            }
            Object services = ((Map<String, Object>) root).get("services");
            if (!(services instanceof List)) {
                return out;
            }
            for (Object item : (List<Object>) services) {
                if (item instanceof Map) {
                    Map<String, Object> m = (Map<String, Object>) item;
                    out.add(new ServiceEntry(str(m.get("name")), str(m.getOrDefault("exposure", "private")), str(m.get("url"))));
                }
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    private String str(Object o) {
        return o == null ? null : o.toString();
    }
}
