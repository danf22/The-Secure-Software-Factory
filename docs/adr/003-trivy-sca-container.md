# ADR-003: Trivy for Software Composition Analysis and Container Scanning

## Status

Accepted

## Date

2025-01-15

## Context

The Secure Software Factory requires two distinct scanning capabilities:

1. **Software Composition Analysis (SCA)**: Detect known CVEs in third-party dependencies (Python packages from `requirements.txt` / `pyproject.toml`)
2. **Container Scanning**: Detect vulnerabilities and misconfigurations in Docker images (OS packages, application libraries, Dockerfile issues)

These are logically different scanning layers in the defense-in-depth model but share overlapping detection databases (CVE feeds, NVD). Using a single tool for both reduces operational complexity while maintaining distinct scan phases.

Key constraints:
- Must detect known CVEs in Python dependencies (SCA layer)
- Must scan container images for OS-level and app-level vulnerabilities
- Must produce SARIF output for both scan types
- Must run within the 10-minute pipeline budget (combined)
- Must support offline/cached vulnerability databases for reproducibility

## Decision

Use **Trivy** for both Software Composition Analysis (`trivy fs`) and Container Scanning (`trivy image`), running as two separate pipeline jobs to maintain scanning layer independence.

## Alternatives Considered

### Alternative 1: Snyk (Commercial — SCA + Container)

- **Pros:** Excellent vulnerability database with proprietary research, fix suggestions with automated PRs, license compliance, container scanning, developer-friendly UI
- **Cons:** Per-project pricing ($25-$99/dev/month = $7.5K–$30K/year), proprietary database not auditable, requires network connectivity to Snyk API, data transmitted to Snyk cloud

### Alternative 2: Grype (OSS — SCA) + Trivy (Container)

- **Pros:** Grype has excellent accuracy for SCA, Anchore-maintained, SARIF support
- **Cons:** Two separate tools to maintain, different configuration paradigms, duplicated vulnerability database management, operational overhead for minimal benefit

### Alternative 3: OWASP Dependency-Check (SCA) + Clair (Container)

- **Pros:** OWASP brand trust, Dependency-Check has good Java/Python support, Clair is well-established for containers
- **Cons:** Dependency-Check is slow (minutes per scan), Clair requires server infrastructure, neither has native SARIF output, two separate ecosystems to manage

### Alternative 4: GitHub Dependabot (SCA) + Docker Scout (Container)

- **Pros:** Native GitHub integration, automatic PR creation for fixes, Docker Scout integrated with Docker Hub
- **Cons:** Dependabot limited to GitHub ecosystem and automated PRs (no SARIF in pipeline), Docker Scout requires Docker subscription for advanced features, neither produces SARIF suitable for custom aggregation, limited custom policy support

### Alternative 5: Snyk Container + Snyk Open Source (Commercial — unified)

- **Pros:** Single vendor for both, excellent fix guidance, priority scoring
- **Cons:** High cost ($30K+/year at production scale), vendor lock-in, cloud-dependent analysis

## Consequences / Trade-offs

### Positive

- Single tool for two scanning layers reduces operational complexity
- Zero licensing cost with community vulnerability database
- Native SARIF output for both `trivy fs` and `trivy image` modes
- Fast execution (~15-30s for SCA, ~30-60s for container scanning)
- Offline database mode supports air-gapped or cached builds
- Active development by Aqua Security with frequent database updates
- Supports multiple ecosystems (Python, Go, Node, etc.) for future growth
- Detects both CVEs and misconfigurations in container images
- Single binary deployment with no server infrastructure required

### Negative

- Vulnerability database may lag 24-48 hours behind NVD for new CVEs
- No automated fix PRs (unlike Snyk/Dependabot) — remediation requires manual updates
- Less granular prioritization compared to commercial tools (no reachability analysis)
- Combined tool means a Trivy upgrade affects both scanning layers simultaneously
- Community support (GitHub issues) vs. dedicated commercial support SLA

## False-Positive Management Strategy

1. **`.trivyignore` file**: Known false positives and accepted risks are documented in a `.trivyignore` file with comments explaining the justification for each suppression.
2. **Severity threshold filtering**: Only `CRITICAL` and `HIGH` severity CVEs trigger policy gate failures. `MEDIUM` and `LOW` are reported for awareness but do not block.
3. **Fixed-version verification**: Before suppressing a finding, verify whether a fix exists. Findings with available fixes are never suppressed — only disputed or unfixable findings qualify.
4. **VEX (Vulnerability Exploitability eXchange)**: For container scanning, use Trivy's VEX support to mark vulnerabilities as "not affected" when the vulnerable code path is not reachable in the application context.
5. **Database pinning in CI**: Pin the vulnerability database version per pipeline run to ensure reproducible results and prevent flapping from database updates mid-sprint.
6. **Monthly review cycle**: Suppressed findings are reviewed monthly to check if fixes have become available or if the risk assessment has changed.

## OSS vs Commercial Justification

Trivy was chosen over commercial alternatives (Snyk, Docker Scout) for the following reasons:

| Factor | Trivy (OSS) | Snyk | Docker Scout |
|--------|-------------|------|-------------|
| Annual cost | $0 | $7.5K–$30K | Varies (Docker subscription) |
| SCA + Container | Single tool | Separate products | Container-focused |
| SARIF output | Native (both modes) | Via CLI flag | Limited |
| Offline/air-gap | Supported | No (cloud-dependent) | No |
| Custom policies | Via OPA integration | Limited | Limited |
| Data residency | Local only | Cloud analysis | Cloud analysis |
| Fix suggestions | No (manual) | Yes (automated PRs) | Yes |
| Database freshness | ~24h lag | Real-time | Real-time |

The trade-off of accepting ~24h database lag and manual remediation (vs. automated fix PRs) is acceptable because:
1. the organization's threat model prioritizes known CVE detection over zero-day response speed
2. The waiver mechanism handles time-bound exceptions for remediation planning
3. Cost savings ($7.5K–$30K/year) fund engineering time for security automation
4. Local-only execution meets CNBV data handling requirements without external data transmission

## References

- [Trivy GitHub Repository](https://github.com/aquasecurity/trivy)
- [Trivy SARIF Output](https://aquasecurity.github.io/trivy/latest/docs/configuration/reporting/#sarif)
- [Trivy Filesystem Scanning](https://aquasecurity.github.io/trivy/latest/docs/target/filesystem/)
- [Trivy Container Image Scanning](https://aquasecurity.github.io/trivy/latest/docs/target/container_image/)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
