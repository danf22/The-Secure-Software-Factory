# ADR-004: Checkov for Infrastructure-as-Code Scanning

## Status

Accepted

## Date

2025-01-15

## Context

The the platform uses Terraform to define cloud infrastructure (AWS S3 buckets, IAM policies, security groups). Infrastructure misconfigurations are a critical risk vector — a public S3 bucket or overly permissive IAM policy could expose financial data or create unauthorized access paths. The IaC scanner must detect these misconfigurations before deployment, integrate with the policy-as-code gate, and support custom checks aligned to the organization's regulatory requirements (CNBV/IFPE, SOC 2).

Key constraints:
- Must scan Terraform HCL files for security misconfigurations
- Must support custom check authoring for the organization-specific policies
- Must produce SARIF output for the aggregation pipeline
- Must integrate with or complement OPA/Conftest for policy enforcement
- Must detect: unencrypted storage, IAM wildcards, overly permissive security groups, missing logging

## Decision

Use **Checkov** as the Infrastructure-as-Code scanning tool, leveraging both its built-in checks and custom Python-based checks for the organization-specific policies.

## Alternatives Considered

### Alternative 1: tfsec (now part of Trivy)

- **Pros:** Fast execution, Terraform-focused, good default rules, now integrated into Trivy ecosystem
- **Cons:** Being deprecated in favor of Trivy IaC scanning (future maintenance risk), custom rule authoring in Rego/JSON (less flexible than Python), SARIF output requires additional formatting, limited to Terraform/CloudFormation

### Alternative 2: Terraform Sentinel (HashiCorp Commercial)

- **Pros:** Native Terraform Cloud/Enterprise integration, policy-as-code designed for Terraform, team management features
- **Cons:** Requires Terraform Cloud/Enterprise license ($70/user/month = $21K/year), proprietary policy language, only works within HashiCorp ecosystem, no SARIF output, cannot run standalone in GitHub Actions without Terraform Cloud

### Alternative 3: OPA/Conftest alone (for IaC)

- **Pros:** Already used for policy gate (reuse), Rego is powerful, highly flexible
- **Cons:** Requires converting Terraform to JSON plan first (terraform plan -json), no built-in IaC security rules (must write all from scratch), high initial investment for comprehensive coverage, no SARIF output

### Alternative 4: Snyk IaC (Commercial)

- **Pros:** Managed service, good accuracy, fix suggestions, IDE integration
- **Cons:** Per-project pricing (included in Snyk bundle $25-99/dev/month), cloud-dependent scanning, limited custom rule flexibility, another vendor dependency

### Alternative 5: KICS (Keeping Infrastructure as Code Secure)

- **Pros:** Open-source (Checkmarx), multi-framework support, good rule coverage
- **Cons:** Slower execution than Checkov, less active community, custom rules require more boilerplate, SARIF support less mature

## Consequences / Trade-offs

### Positive

- Zero licensing cost with 1000+ built-in security checks
- Custom checks written in Python — accessible to the entire the engineering team
- Native SARIF output integrates directly with the aggregation pipeline
- Supports Terraform, CloudFormation, Kubernetes, Dockerfile, and more (future-proofing)
- Built-in checks cover CIS benchmarks, SOC 2, and other compliance frameworks
- Fast execution (~10-20s for typical Terraform projects)
- Active open-source community (Bridgecrew/Palo Alto) with frequent updates
- Can scan Terraform plan JSON for runtime value analysis

### Negative

- Python-based tool adds Python runtime dependency to the CI environment (already present for the organization)
- Custom check development requires Python knowledge (vs. Rego for OPA/Conftest)
- Some overlap with OPA/Conftest policies creates potential for duplicate findings
- Built-in checks may be overly broad for the organization's specific AWS configuration
- Bridgecrew platform (commercial layer) adds upsell pressure

## False-Positive Management Strategy

1. **`.checkov.baseline` file**: Baseline existing findings that have been reviewed and accepted. New findings above baseline trigger alerts.
2. **Inline skip comments**: Use `# checkov:skip=CKV_AWS_XXX: <justification>` for code-level suppressions with mandatory justification text.
3. **Custom check precision**: organization-specific custom checks are written with narrow scope to avoid firing on intentionally permissive configurations (e.g., CDN-facing security groups).
4. **Check selection via `--check` and `--skip-check`**: Disable checks that consistently produce false positives for the organization's architecture (documented in pipeline configuration).
5. **Severity filtering**: Only `HIGH` and `CRITICAL` findings from built-in checks trigger policy gate failures. Custom policy checks always enforce regardless of severity level.
6. **Environment-aware scanning**: Use different check configurations for production vs. development Terraform (dev may legitimately have broader permissions).

## OSS vs Commercial Justification

Checkov was chosen over commercial alternatives (Terraform Sentinel, Snyk IaC) for the following reasons:

| Factor | Checkov (OSS) | Terraform Sentinel | Snyk IaC |
|--------|---------------|-------------------|-----------|
| Annual cost | $0 | ~$21K (TF Enterprise) | ~$15K (bundle) |
| Custom checks | Python (flexible) | Sentinel language | Limited |
| SARIF output | Native | No | Via API |
| Standalone CI | Yes | Requires TF Cloud | Yes (cloud-dependent) |
| Built-in rules | 1000+ | ~100 | ~300 |
| Multi-framework | TF, K8s, Docker, CF | Terraform only | TF, K8s, CF |
| Data residency | Local only | HashiCorp Cloud | Snyk Cloud |

Checkov provides comprehensive IaC scanning with custom check flexibility that aligns with the organization's need for CNBV/IFPE-specific policy enforcement. The Python-based custom checks integrate naturally with the existing Python toolchain. The zero licensing cost is redirected toward engineering time for custom check development specific to Mexican financial regulatory requirements.

## References

- [Checkov GitHub Repository](https://github.com/bridgecrewio/checkov)
- [Checkov Custom Checks Guide](https://www.checkov.io/3.Custom%20Policies/Custom%20Policies%20Overview.html)
- [Checkov SARIF Output](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Bridgecrew Compliance Frameworks](https://www.checkov.io/4.Integrations/compliance.html)
