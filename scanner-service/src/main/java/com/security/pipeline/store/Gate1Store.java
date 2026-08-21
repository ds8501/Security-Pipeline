package com.security.pipeline.store;

import com.security.pipeline.entity.Gate1Run;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/** In-memory store for Gate-1 runs (mirrors {@link ScanStore}). */
@Component
public class Gate1Store {
    private final ConcurrentHashMap<Long, Gate1Run> runs = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong(0);

    public Gate1Run save(Gate1Run run) {
        if (run.getId() == null) {
            run.setId(sequence.incrementAndGet());
        }
        runs.put(run.getId(), run);
        return run;
    }

    public Optional<Gate1Run> findById(Long id) {
        return Optional.ofNullable(runs.get(id));
    }

    public List<Gate1Run> findAllByCreatedAtDesc() {
        return runs.values().stream()
                .sorted(Comparator.comparing(Gate1Run::getCreatedAt).reversed())
                .collect(Collectors.toList());
    }
}
