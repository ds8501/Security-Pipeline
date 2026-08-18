package com.security.pipeline.store;

import com.security.pipeline.entity.Scan;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * In-memory replacement for the old JPA repository. Scans live only for the process lifetime
 * (the previous H2 database was in-memory too, so this changes nothing observable). Because the
 * stored {@link Scan} objects are mutated in place by the background review thread, callers read
 * them live — the copy-on-write collections on {@link Scan} keep concurrent reads safe.
 */
@Component
public class ScanStore {
    private final ConcurrentHashMap<Long, Scan> scans = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong(0);

    public Scan save(Scan scan) {
        if (scan.getId() == null) {
            scan.setId(sequence.incrementAndGet());
        }
        scans.put(scan.getId(), scan);
        return scan;
    }

    public Optional<Scan> findById(Long id) {
        return Optional.ofNullable(scans.get(id));
    }

    public List<Scan> findAllByCreatedAtDesc() {
        return scans.values().stream()
                .sorted(Comparator.comparing(Scan::getCreatedAt).reversed())
                .collect(Collectors.toList());
    }
}
