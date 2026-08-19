package com.security.pipeline.repository;

import com.security.pipeline.entity.Finding;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingRepository extends JpaRepository<Finding, Long> {
}
