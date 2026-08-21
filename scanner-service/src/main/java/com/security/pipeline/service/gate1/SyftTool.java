package com.security.pipeline.service.gate1;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.List;

/**
 * Gate-1 software bill of materials via Syft. This is inventory, not a vulnerability check, so it
 * never produces findings — it reports how many components were catalogued and always passes.
 */
@Component
public class SyftTool extends AbstractProcessTool {

    @Value("${secgate.syft-binary:syft}")
    private String binary;

    @Override
    public String id() {
        return "syft";
    }

    @Override
    public String label() {
        return "Syft (SBOM)";
    }

    @Override
    public int order() {
        return 50;
    }

    @Override
    public Gate1Result scan(Path repoDir) {
        ProcessOutcome outcome = run(repoDir, List.of(binary, ".", "-o", "cyclonedx-json", "-q"), 180);
        if (!outcome.started()) {
            return Gate1Result.unavailable(id(), "Syft binary not found");
        }
        if (outcome.timedOut()) {
            return new Gate1Result(id(), Gate1Result.FAIL, "Syft timed out", List.of());
        }

        try {
            String out = outcome.output();
            int brace = out.indexOf('{');
            int count = 0;
            if (brace >= 0) {
                JsonNode root = objectMapper.readTree(out.substring(brace));
                JsonNode components = root.path("components");
                if (components.isArray()) {
                    count = components.size();
                }
            }
            return new Gate1Result(id(), Gate1Result.PASS, "SBOM generated: " + count + " component(s)", List.of());
        } catch (Exception e) {
            return new Gate1Result(id(), Gate1Result.PASS, "SBOM generated (component count unavailable)", List.of());
        }
    }
}
