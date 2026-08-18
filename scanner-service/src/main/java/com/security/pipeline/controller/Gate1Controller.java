package com.security.pipeline.controller;

import com.security.pipeline.entity.Gate1Run;
import com.security.pipeline.service.Gate1Service;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/gate1")
public class Gate1Controller {
    private final Gate1Service gate1Service;

    public Gate1Controller(Gate1Service gate1Service) {
        this.gate1Service = gate1Service;
    }

    @GetMapping
    public List<Gate1Run> getRuns() {
        return gate1Service.getRuns();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Gate1Run> getRun(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(gate1Service.getRun(id));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(404).build();
        }
    }

    @PostMapping
    public ResponseEntity<Gate1Run> start(@RequestBody(required = false) Gate1Request request) {
        Gate1Request req = request == null ? new Gate1Request(null, null, null, null) : request;
        return ResponseEntity.accepted().body(gate1Service.start(req));
    }
}
