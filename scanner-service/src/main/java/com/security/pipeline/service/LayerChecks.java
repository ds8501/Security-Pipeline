package com.security.pipeline.service;

import com.security.pipeline.entity.Finding;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Deterministic Gate 2 layer checks (L2–L6 from the design doc). These are regex/heuristic passes
 * over the added lines of the diff — no LLM needed — so they always run and are unit-testable. The
 * AI-review layer (L1) covers the reasoning-heavy cases; this catches the concrete, provable ones.
 * Every finding is marked CONFIRMED because the detection pattern actually fired (doc's "proof" idea).
 */
@Component
public class LayerChecks {
    public static final String DATA = "Data protection";
    public static final String ACCESS = "Access & identity";
    public static final String FAILURE = "Failure behaviour";
    public static final String SUPPLY = "Supply chain";
    public static final String RELEASE = "Release safety";

    private static final Pattern WEAK_CIPHER = Pattern.compile("(?i)\\b(3?DES|DESede|RC4|ARCFOUR)\\b|(?i)/ECB/|(?i)AES/ECB");
    private static final Pattern WEAK_HASH = Pattern.compile("(?i)\\b(md5|sha-?1)\\b");
    private static final Pattern HARDCODED_SECRET = Pattern.compile("(?i)(secret|password|api[_-]?key|token)\\s*[=:]\\s*[\"'][^\"']{6,}[\"']");
    private static final Pattern PII = Pattern.compile("(?i)\\b(ssn|social_security|aadhaar|passport|date_of_birth|dob|phone_number)\\b");
    private static final Pattern COLUMN_CTX = Pattern.compile("(?i)(@column|add\\s+column|addcolumn|alter\\s+table|create\\s+table)");
    private static final Pattern PII_IN_LOG = Pattern.compile("(?i)(log(ger)?|system\\.out)\\s*\\.\\s*(print|println|info|debug|warn|error|trace)\\s*\\(.*(password|secret|token|ssn|aadhaar|passport|email|phone)");
    private static final Pattern MAPPING = Pattern.compile("@(Get|Post|Put|Delete|Patch|Request)Mapping");
    private static final Pattern AUTH_ANNOTATION = Pattern.compile("(?i)@PreAuthorize|@Secured|@RolesAllowed|isAuthenticated|authenticated\\s*\\(|@RequirePermission");
    private static final Pattern PERMIT_ALL = Pattern.compile("permitAll\\s*\\(");
    private static final Pattern STACKTRACE_LEAK = Pattern.compile("printStackTrace\\s*\\(");
    private static final Pattern DROP_STMT = Pattern.compile("(?i)\\bDROP\\s+(TABLE|COLUMN)\\b");
    private static final List<String> MANIFESTS = List.of(
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pom.xml", "build.gradle",
            "requirements.txt", "go.sum", "go.mod", "cargo.lock");

    /** Analyze a diff and return layer findings. {@code rawDiff} is a unified git diff. */
    public List<Finding> analyze(String rawDiff, List<String> changedFiles) {
        List<Finding> out = new ArrayList<>();
        Map<String, List<String>> addedByFile = addedLinesByFile(rawDiff);

        for (Map.Entry<String, List<String>> e : addedByFile.entrySet()) {
            String file = e.getKey();
            List<String> lines = e.getValue();
            boolean fileHasMapping = false;
            boolean fileHasAuth = false;

            for (String line : lines) {
                if (WEAK_CIPHER.matcher(line).find()) {
                    out.add(f("Weak or broken cipher", "HIGH", file, DATA, line,
                            "Use AES-256-GCM or ChaCha20; avoid DES/3DES/RC4/ECB.", "CWE-327", "A02:2021"));
                }
                if (WEAK_HASH.matcher(line).find() && !line.toLowerCase().contains("sha-256") && !line.contains("SHA-512")) {
                    out.add(f("Weak hash (MD5/SHA-1)", "HIGH", file, DATA, line,
                            "Hash passwords with Argon2 or bcrypt; use SHA-256+ for integrity.", "CWE-328", "A02:2021"));
                }
                if (HARDCODED_SECRET.matcher(line).find()) {
                    out.add(f("Possible hardcoded secret", "MEDIUM", file, DATA, line,
                            "Move secrets to a vault / env var; never commit them.", "CWE-798", "A05:2021"));
                }
                if (PII.matcher(line).find() && COLUMN_CTX.matcher(line).find()) {
                    out.add(f("PII column may be unencrypted", "MEDIUM", file, DATA, line,
                            "Encrypt PII at rest (e.g. column encryption) and document retention.", "CWE-311", "A02:2021"));
                }
                if (PII_IN_LOG.matcher(line).find()) {
                    out.add(f("Sensitive data written to logs", "MEDIUM", file, DATA, line,
                            "Redact secrets/PII before logging.", "CWE-532", "A09:2021"));
                }
                if (PERMIT_ALL.matcher(line).find()) {
                    out.add(f("Endpoint opened with permitAll()", "MEDIUM", file, ACCESS, line,
                            "Default to deny; require authentication/authorization.", "CWE-284", "A01:2021"));
                }
                if (STACKTRACE_LEAK.matcher(line).find()) {
                    out.add(f("Stack trace may leak to output", "LOW", file, FAILURE, line,
                            "Log server-side; return a generic error to clients.", "CWE-209", "A05:2021"));
                }
                if (DROP_STMT.matcher(line).find()) {
                    out.add(f("Potentially irreversible migration", "MEDIUM", file, RELEASE, line,
                            "Provide a reversible/down migration and avoid locking large tables.", "CWE-0", "A08:2021"));
                }
                if (MAPPING.matcher(line).find()) {
                    fileHasMapping = true;
                }
                if (AUTH_ANNOTATION.matcher(line).find()) {
                    fileHasAuth = true;
                }
            }
            if (fileHasMapping && !fileHasAuth) {
                out.add(f("New endpoint without visible authorization", "MEDIUM", file, ACCESS,
                        "@*Mapping added without @PreAuthorize/@Secured/@RolesAllowed nearby",
                        "Add an authorization check (deny by default).", "CWE-862", "A01:2021"));
            }
        }

        // Supply chain — dependency manifests / lockfiles changed in this diff.
        if (changedFiles != null) {
            for (String cf : changedFiles) {
                String name = cf.substring(cf.lastIndexOf('/') + 1).toLowerCase();
                if (MANIFESTS.contains(name)) {
                    out.add(f("Dependency manifest changed: " + name, "LOW", cf, SUPPLY,
                            "New or updated dependencies in " + cf,
                            "Review added packages for typo-squats and unexplained lockfile changes.", "CWE-1104", "A06:2021"));
                }
            }
        }
        return out;
    }

    private Finding f(String title, String sev, String file, String layer, String evidence, String fix, String cwe, String owasp) {
        Finding finding = new Finding();
        finding.setTitle(title);
        finding.setSeverity(sev);
        finding.setFile(file);
        finding.setLayer(layer);
        finding.setDescription(layer + " — " + evidence.trim());
        finding.setFix(fix);
        finding.setCwe(cwe);
        finding.setOwasp(owasp);
        finding.setProofStatus("CONFIRMED");
        finding.setProof("Detection rule fired on: " + evidence.trim());
        return finding;
    }

    /** Map of file → added lines (lines starting with '+' but not the '+++' header) from a unified diff. */
    private Map<String, List<String>> addedLinesByFile(String rawDiff) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        if (rawDiff == null) {
            return map;
        }
        String current = "unknown";
        for (String line : rawDiff.split("\\R")) {
            if (line.startsWith("+++ ")) {
                current = line.substring(4).replaceFirst("^b/", "").trim();
                map.computeIfAbsent(current, k -> new ArrayList<>());
            } else if (line.startsWith("+") && !line.startsWith("+++")) {
                map.computeIfAbsent(current, k -> new ArrayList<>()).add(line.substring(1));
            }
        }
        return map;
    }
}
