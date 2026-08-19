package com.security.pipeline.service;

import com.security.pipeline.entity.Finding;
import com.security.pipeline.service.layer.ReviewLayer;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Coordinates the Gate-2 AI review layers (L2-L6). Each {@link ReviewLayer} is a focused,
 * single-category pass; this service holds them in execution order and exposes them so the
 * scan pipeline can run them one at a time and report per-layer progress.
 *
 * <p>Layer L1 (prompt-injection / integrity) is handled separately by {@link IntegrityService}.
 */
@Service
public class ReviewService {
    private final List<ReviewLayer> layers;

    public ReviewService(List<ReviewLayer> layers) {
        this.layers = layers == null ? List.of() : layers.stream()
                .sorted(Comparator.comparingInt(ReviewLayer::order))
                .toList();
    }

    /** The review layers in execution order (L2, L3, ... L6). */
    public List<ReviewLayer> getLayers() {
        return layers;
    }

    /**
     * Runs every layer in order and returns the aggregated findings. Callers that want
     * per-layer progress should instead iterate {@link #getLayers()} and invoke each layer
     * directly.
     */
    public List<Finding> review(DiffContext diffContext) {
        List<Finding> all = new ArrayList<>();
        for (ReviewLayer layer : layers) {
            all.addAll(layer.review(diffContext));
        }
        return all;
    }
}
