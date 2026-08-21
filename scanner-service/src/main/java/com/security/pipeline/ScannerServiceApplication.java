package com.security.pipeline;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class ScannerServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(ScannerServiceApplication.class, args);
    }
}
