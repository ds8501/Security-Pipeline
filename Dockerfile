# Build the Spring Boot service in a disposable Maven image, then copy only the
# executable JAR into the final runtime image.
FROM maven:3.9.9-eclipse-temurin-17 AS build

WORKDIR /workspace/scanner-service

# Resolve dependencies separately so Docker can reuse this layer when only
# application source changes.
COPY scanner-service/pom.xml ./pom.xml
RUN mvn --batch-mode --no-transfer-progress dependency:go-offline

COPY scanner-service/src ./src
RUN mvn --batch-mode --no-transfer-progress -DskipTests package

# JDK (not JRE) base so Gate 1's "mvn test" check can compile & run tests in-process.
FROM eclipse-temurin:17-jdk-jammy AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Base utilities + tools Gate 1 shells out to in local (API) mode:
#   git, ripgrep (repo + hotspot checks), maven (unit tests), semgrep (SAST).
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates curl git ripgrep maven python3 python3-pip tar \
    && pip3 install --no-cache-dir semgrep \
    && rm -rf /var/lib/apt/lists/*

# Single-binary Gate 1 scanners: gitleaks, osv-scanner, trivy, syft.
RUN set -eux; \
    curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
        | tar -xz -C /usr/local/bin gitleaks; \
    curl -sSL -o /usr/local/bin/osv-scanner \
        https://github.com/google/osv-scanner/releases/download/v2.5.1/osv-scanner_linux_amd64; \
    chmod +x /usr/local/bin/osv-scanner; \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin; \
    curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin; \
    gitleaks version && osv-scanner --version && syft version && trivy --version && semgrep --version && mvn -v

WORKDIR /app
COPY --from=build /workspace/scanner-service/target/scanner-service-*.jar /app/app.jar

# Cap the JVM heap at ~40% so Gate 1's tool subprocesses (Semgrep etc.) have room
# on a 512MB host. Tools run sequentially, so peak = heap + one tool at a time.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=40.0 -Djava.security.egd=file:/dev/./urandom"
EXPOSE 8080

# Render supplies PORT at runtime. The fallback keeps local Docker usage simple.
CMD ["sh", "-c", "exec java -jar /app/app.jar --server.port=${PORT:-8080}"]
