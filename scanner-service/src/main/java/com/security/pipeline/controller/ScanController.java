package com.security.pipeline.controller;

import com.security.pipeline.entity.Scan;
import com.security.pipeline.service.ScanService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api")
public class ScanController {
    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("ok");
    }

    @GetMapping("/scans")
    public List<Scan> getScans() {
        return scanService.getScans();
    }

    @GetMapping("/scans/{id}")
    public Scan getScan(@PathVariable Long id) {
        return scanService.getScan(id);
    }

    @PostMapping("/scans")
    public ResponseEntity<Scan> createScan(@Valid @RequestBody ScanRequest request) {
        return ResponseEntity.accepted().body(scanService.createScan(request.repoUrl(), request.branch()));
    }
}
