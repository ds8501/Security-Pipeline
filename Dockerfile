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

FROM eclipse-temurin:17-jre-jammy AS runtime

# Git and ripgrep enable the service's repository and hotspot checks. The
# remaining optional security tools still degrade gracefully when unavailable.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git ripgrep \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /workspace/scanner-service/target/scanner-service-*.jar /app/app.jar

ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"
EXPOSE 8080

# Render supplies PORT at runtime. The fallback keeps local Docker usage simple.
CMD ["sh", "-c", "exec java -jar /app/app.jar --server.port=${PORT:-8080}"]
