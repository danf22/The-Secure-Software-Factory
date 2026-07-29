# ADR-002: Semgrep for Static Application Security Testing (SAST)

## Status

Accepted

## Date

2025-01-15

## Context

The the platform requires Static Application Security Testing to detect code-level vulnerabilities such as injection flaws, insecure deserialization, and unsafe patterns in the Python/FastAPI codebase. The SAST tool must integrate into both the CI pipeline and pre-commit hooks, support Python natively, produce SARIF output, and provide a rule authoring mechanism for the organization-specific patterns (e.g., unsafe treasury operations, FX rate handling).

Key constraints:
- Must support Python and FastAPI idioms natively
- Must produce SARIF 2.1.0 output for the aggregation pipeline
- Must run within the 10-minute total pipeline budget
- Must support custom rule authoring for fintech-specific patterns
- Must support a lightweight mode for pre-commit hooks (<30s)

## Decision

Use **Semgrep** (OSS engine with community rules) as the SAST scanner for the security pipeline and pre-commit hooks.

## Alternatives Considered

### Alternative 1: SonarQube Community Edition

- **Pros:** Broad language support, quality gates, historical trend analysis, well-known in enterprise environments
- **Cons:** Requires server infrastructure (SonarQube server + database), slower analysis cycle, limited custom rule authoring in community edition, no native SARIF output, heavy resource footprint for CI, community edition lacks branch analysis

### Alternative 2: CodeQL (GitHub)

- **Pros:** Deep semantic analysis, excellent for finding complex vulnerabilities (taint tracking), native GitHub integration, free for public repos
- **Cons:** Requires GitHub Advanced Security license for private repos ($49/committer/month), slow analysis (5-15 min for medium codebases), complex query language (QL) for custom rules, not suitable for pre-commit hooks due to database compilation step

### Alternative 3: Bandit (Python-specific)

- **Pros:** Python-native, fast, simple configuration, well-known in Python community
- **Cons:** Python-only (no support for future polyglot growth), limited rule set, no SARIF output without adapters, no custom rule language, limited pattern matching capabilities

### Alternative 4: Snyk Code (Commercial)

- **Pros:** AI-powered analysis, low false-positive rate, IDE integrations, managed service with dashboard
- **Cons:** Per-developer pricing ($52/dev/month = ~$15.6K/year), proprietary rules not auditable, data sent to Snyk cloud for analysis, limited offline/air-gapped operation

### Alternative 5: Checkmarx (Commercial)

- **Pros:** Enterprise-grade, comprehensive language coverage, compliance reporting
- **Cons:** High licensing cost ($50K+/year for 25 developers), complex deployment, slow scan times, vendor lock-in, overkill for current team size

## Consequences / Trade-offs

### Positive

- Zero licensing cost for OSS engine and community rules
- Fast execution (typically 10-30s for medium Python projects)
- Intuitive YAML-based rule authoring — any engineer can write custom rules
- Native SARIF output integrates directly with the aggregation pipeline
- Supports pre-commit hooks with configurable rule subsets for speed
- Active community with 2000+ security rules maintained by r2c/Semgrep
- Pattern-based matching easy to understand and audit (vs. opaque AI/ML approaches)
- Runs locally without network access — no code leaves the build environment

### Negative

- Pattern-based analysis misses some complex inter-procedural vulnerabilities that taint-tracking tools (CodeQL) would catch
- Community rules may lag behind emerging vulnerability patterns
- No built-in historical trend dashboard (requires custom reporting)
- Pro/Enterprise features (Semgrep Supply Chain, RBAC) require paid tier
- Rule maintenance is an ongoing operational cost for the security team

## False-Positive Management Strategy

1. **Rule tuning via `semgrep.yml`**: Overly broad community rules are disabled or narrowed using path/pattern exclusions in the project-level Semgrep configuration.
2. **Inline suppression with audit trail**: Engineers can add `# nosemgrep: <rule-id>` with a mandatory comment justifying the suppression. These are tracked in code review.
3. **Confidence-based filtering**: Only `ERROR` and `WARNING` level findings block the pipeline; `INFO` level findings are collected for reporting but do not gate builds.
4. **Test file exclusion**: Test directories (`tests/`, `*_test.py`) are excluded from security rules that would fire on intentionally vulnerable test fixtures.
5. **Custom rule precision**: organization-specific rules are written with narrow patterns to minimize false positives — reviewed by both security and application engineers before deployment.
6. **Quarterly metrics review**: False-positive rate is tracked per rule. Rules exceeding 30% false-positive rate are revised or demoted to informational severity.

## OSS vs Commercial Justification

Semgrep OSS was chosen over commercial alternatives for the following reasons:

| Factor | Semgrep OSS | SonarQube | Snyk Code | Checkmarx |
|--------|-------------|-----------|-----------|-----------|
| Annual cost | $0 | $0 (community) / $15K+ (enterprise) | ~$15.6K | $50K+ |
| Custom rules | YAML (simple) | Java (complex) | Limited | Proprietary |
| SARIF output | Native | Requires plugin | Via API | Via export |
| Pre-commit | Supported | Not practical | IDE only | No |
| Data residency | Local only | Self-hosted | Cloud | Self-hosted/Cloud |
| Setup complexity | Single binary | Server + DB | SaaS | Server infrastructure |
| Python support | Excellent | Good | Good | Good |

For the organization's current scale (25 engineers, primarily Python), Semgrep provides the best balance of detection capability, speed, and operational simplicity. The zero licensing cost allows investing engineering time in custom rules specific to fintech patterns. The local-only execution model aligns with CNBV data handling requirements.

## References

- [Semgrep GitHub Repository](https://github.com/semgrep/semgrep)
- [Semgrep Rule Registry](https://semgrep.dev/explore)
- [Semgrep SARIF Output](https://semgrep.dev/docs/cli-reference/#sarif-output)
- [Writing Custom Semgrep Rules](https://semgrep.dev/docs/writing-rules/overview/)
- [OWASP Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)
