# ADR-001: Gitleaks for Secrets Scanning

## Status

Accepted

## Date

2025-01-15

## Context

The Secure Software Factory requires automated detection of hardcoded secrets, API keys, credentials, and tokens in source code and git history. With ~25 engineers across 5 teams, secrets leakage is a high-probability risk that can lead to unauthorized access to financial systems, regulatory violations (CNBV/IFPE), and SOC 2 non-compliance.

The secrets scanner must:
- Detect secrets in both staged commits (pre-commit) and full repository history (CI)
- Produce SARIF output for integration with the aggregated reporting pipeline
- Run fast enough for pre-commit hooks (<30s) and CI pipelines (<10 min total)
- Support custom regex patterns for the organization-specific secret formats (e.g., internal API key patterns)

## Decision

Use **Gitleaks** as the secrets scanning tool for both pre-commit hooks and CI pipeline execution.

## Alternatives Considered

### Alternative 1: TruffleHog

- **Pros:** Verified secret detection (checks if secrets are live), supports 700+ detectors, active development by Truffle Security
- **Cons:** Slower execution due to verification step, heavier resource consumption, SARIF output requires additional formatting, pre-commit integration less mature than Gitleaks

### Alternative 2: detect-secrets (Yelp)

- **Pros:** Lightweight, good baseline file support for managing known secrets, Python-native
- **Cons:** Fewer built-in patterns, no native SARIF output, limited git history scanning, slower community development cadence

### Alternative 3: GitGuardian (Commercial)

- **Pros:** Managed SaaS with dashboard, excellent detection accuracy, team collaboration features, incident management
- **Cons:** Per-developer pricing (~$40/dev/month = ~$12K/year for 25 engineers), vendor lock-in, data leaves the build environment, limited custom rule flexibility

### Alternative 4: GitHub Advanced Security - Secret Scanning

- **Pros:** Native GitHub integration, push protection, partner program for auto-revocation
- **Cons:** Requires GitHub Enterprise ($21/user/month), limited custom patterns on non-Enterprise tiers, no local pre-commit capability, cannot run outside GitHub ecosystem

## Consequences / Trade-offs

### Positive

- Zero licensing cost for the tool itself
- Native SARIF output simplifies pipeline integration
- Fast execution (~5-10s for typical repos) supports both pre-commit and CI use
- Excellent pre-commit hook support via official integration
- Custom regex support allows organization-specific patterns
- Single binary with no runtime dependencies simplifies deployment
- Active open-source community with frequent releases

### Negative

- No automatic verification of whether detected secrets are still active (unlike TruffleHog)
- No managed dashboard — requires custom reporting via SARIF aggregation
- Regex-based detection has inherent false-positive rate for high-entropy strings
- Team must maintain custom rule configurations as new secret patterns emerge

## False-Positive Management Strategy

1. **Baseline file (`.gitleaksignore`)**: Known false positives are added to an ignore file with a comment explaining why each entry is safe. This file is reviewed quarterly.
2. **Custom allowlist rules**: Patterns that consistently trigger false positives (e.g., test fixtures, example values) are excluded via `gitleaks.toml` allowlist configuration.
3. **Severity-based triage**: Only `critical` and `high` severity findings block the pipeline; `medium` and `low` are reported as warnings for team review.
4. **Pre-commit vs CI differentiation**: Pre-commit runs a fast subset of rules optimized for precision; CI runs the full rule set for comprehensive coverage.
5. **Quarterly rule review**: The security team reviews detection patterns and false-positive rates quarterly, adjusting thresholds and allowlists.

## OSS vs Commercial Justification

Gitleaks was chosen over commercial alternatives (GitGuardian, GitHub Advanced Security) for the following reasons:

| Factor | Gitleaks (OSS) | Commercial |
|--------|---------------|------------|
| Annual cost | $0 | $12K–$25K+ |
| Custom rules | Full regex control | Limited by vendor |
| Data residency | Stays in build env | May leave environment |
| Vendor lock-in | None | High |
| Pre-commit support | Native | Varies |
| SARIF output | Native | Often requires adapters |

For a fintech company pursuing IFPE authorization, keeping secrets detection within the build environment (no external data transmission) is a regulatory advantage. The cost savings fund engineering time to maintain custom rules and the SARIF integration layer.

## References

- [Gitleaks GitHub Repository](https://github.com/gitleaks/gitleaks)
- [Gitleaks SARIF Output Documentation](https://github.com/gitleaks/gitleaks#sarif)
- [Pre-commit Hook Integration](https://github.com/gitleaks/gitleaks#pre-commit)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
