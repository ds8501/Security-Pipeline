package com.security.pipeline.repository;

import com.security.pipeline.entity.Scan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.EntityGraph;

import java.util.List;
import java.util.Optional;

public interface ScanRepository extends JpaRepository<Scan, Long> {
    @EntityGraph(attributePaths = "findings")
    List<Scan> findAllByOrderByCreatedAtDesc();

    @EntityGraph(attributePaths = "findings")
    Optional<Scan> findWithFindingsById(Long id);
}
