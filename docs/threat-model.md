# Threat Model — Secure Software Factory

## 1. Introduction and Scope

This document provides a structured threat model for the Secure Software Factory, covering the CI/CD pipeline infrastructure, the applications it builds, and the supply-chain integrity mechanisms protecting deployed artifacts.

### Scope

| In Scope | Out of Scope |
|----------|--------------|
| GitHub Actions CI/CD pipeline | Runtime application security (WAF, RASP) |
| Source code repositories | Network infrastructure (VPC, firewalls) |
| Container image build and signing | End-user authentication/authorization |
| Third-party dependency supply chain | Physical security of data centers |
| Infrastructure-as-Code definitions | Business logic vulnerabilities beyond seed demo |
| Developer workstation pre-commit hooks | Mobile or client-side attack vectors |
| Policy-as-code enforcement gates | DDoS mitigation |

### Methodology

This threat model uses a hybrid approach combining:
- **STRIDE** categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) for systematic identification
- **Kill-chain mapping** to understand attacker progression
- **Control mapping** to the pipeline layers that mitigate each threat

### Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|------------|
| External attacker | Financial gain, data theft | Moderate — can target public-facing repositories or exploit known CVEs |
| Malicious insider | Sabotage, data exfiltration | High — has legitimate access to code, secrets, and infrastructure |
| Supply-chain adversary | Broad compromise via upstream | High — can inject malicious code into popular packages |
| Compromised CI/CD | Lateral movement, credential theft | High — has access to secrets, build artifacts, and deployment targets |

---

## 2. Threat Categories

### 2.1 Supply-Chain Attacks on Dependencies

#### T-SC-01: Malicious Package Injection

| Attribute | Detail |
|-----------|--------|
| **Description** | An attacker publishes a malicious package to PyPI (or another registry) that mimics a legitimate dependency name (typosquatting) or compromises an existing package's maintainer account to inject malicious code into a new version. |
| **Impact** | Arbitrary code execution within the build environment and production containers. Data exfiltration, backdoor installation, credential theft. |
| **Mitigating Controls** | • **SCA Scanner (Trivy)** — detects known CVEs in dependencies during pipeline execution<br>• **SBOM Generation (Syft)** — provides full dependency inventory for audit and anomaly detection<br>• **Policy Gate** — blocks builds with critical/high CVE findings<br>• **Pre-commit hooks** — early detection of suspicious dependency additions |
| **Residual Risk** | Zero-day malicious packages not yet in CVE databases will pass SCA scanning undetected. Typosquatting attacks on newly added dependencies may not be caught until the CVE is published. No runtime behavioral analysis is in place. |

#### T-SC-02: Dependency Confusion

| Attribute | Detail |
|-----------|--------|
| **Description** | An attacker registers a package on a public registry with the same name as an internal/private package but with a higher version number, causing the package manager to pull the malicious public version. |
| **Impact** | Malicious code execution during build, potential credential harvesting from CI environment variables. |
| **Mitigating Controls** | • **SCA Scanner (Trivy)** — flags unexpected package sources<br>• **SBOM (Syft)** — audit trail shows package provenance<br>• **Pinned dependencies** in `requirements.txt` with exact versions |
| **Residual Risk** | If private registry configuration is not enforced at the pip/package manager level (e.g., `--index-url` pointing to internal registry first), confusion attacks may succeed before scanning occurs. The pipeline does not currently enforce private registry priority. |

#### T-SC-03: Compromised Upstream Repository

| Attribute | Detail |
|-----------|--------|
| **Description** | A legitimate upstream dependency is compromised (e.g., via maintainer account takeover), and a malicious release is published under the trusted package name. |
| **Impact** | Silent introduction of backdoors or data exfiltration code into production builds, affecting all consumers of the package. |
| **Mitigating Controls** | • **SCA Scanner (Trivy)** — detects once CVE is published<br>• **SBOM (Syft)** — enables rapid identification of affected deployments during incident response<br>• **Provenance Attestation (cosign/SLSA)** — proves which dependencies were used in each build |
| **Residual Risk** | Window of exposure between compromise and CVE publication can be days to weeks. No source-level verification (e.g., Sigstore for Python packages) is enforced. |

---

### 2.2 Compromised Build Environment

#### T-BE-01: CI/CD Pipeline Tampering

| Attribute | Detail |
|-----------|--------|
| **Description** | An attacker modifies GitHub Actions workflow files to skip security scanning steps, exfiltrate secrets during builds, or inject malicious code into built artifacts. |
| **Impact** | Complete bypass of security pipeline, deployment of compromised artifacts, exfiltration of signing keys and deployment credentials. |
| **Mitigating Controls** | • **Branch protection rules** — require PR reviews for workflow file changes<br>• **Secrets Scanner (Gitleaks)** — detects if secrets are committed to workflow files<br>• **Provenance Attestation (SLSA)** — records which workflow produced each artifact<br>• **Audit trail** — all pipeline runs and decisions are recorded immutably<br>• **Policy Gate (OPA/Conftest)** — evaluates scan results independently of scanner execution |
| **Residual Risk** | Repository administrators can bypass branch protections. Self-hosted runners (if used) may be compromised at the OS level. GitHub Actions marketplace actions could be backdoored. |

#### T-BE-02: Secrets Exfiltration from Build Environment

| Attribute | Detail |
|-----------|--------|
| **Description** | An attacker exploits a vulnerability in a build step (or a malicious dependency's install script) to read GitHub Actions secrets and exfiltrate them via network calls or encoded in build outputs. |
| **Impact** | Stolen signing keys (cosign), cloud credentials, registry tokens. Enables artifact tampering and unauthorized deployments. |
| **Mitigating Controls** | • **cosign keyless signing (OIDC)** — no persistent signing keys stored in CI<br>• **Secrets Scanner (Gitleaks)** — prevents secrets from being committed<br>• **Minimal secret scope** — secrets available only in specific jobs<br>• **GitHub Actions secret masking** — prevents accidental logging |
| **Residual Risk** | Sophisticated exfiltration via DNS or steganography in build artifacts is not detected. OIDC tokens have a validity window during which they could be stolen. Network egress from CI runners is not restricted. |

#### T-BE-03: Unauthorized Access to CI/CD

| Attribute | Detail |
|-----------|--------|
| **Description** | An attacker gains access to the GitHub organization or repository through compromised developer credentials, stolen PATs, or OAuth app abuse. |
| **Impact** | Ability to trigger pipelines, modify code, access secrets, and approve pull requests. |
| **Mitigating Controls** | • **GitHub branch protection** — require multiple reviewers<br>• **Audit trail** — records all pipeline executions with commit SHA linkage<br>• **Pre-commit hooks** — detect secrets before push<br>• **Per-run summary reports** — anomalous builds can be detected during review |
| **Residual Risk** | Compromised accounts with admin privileges can override protections. No anomaly detection or behavioral analysis on CI/CD access patterns is currently implemented. |

---

### 2.3 Insider Threats

#### T-IN-01: Malicious Developer Introducing Vulnerabilities

| Attribute | Detail |
|-----------|--------|
| **Description** | A developer intentionally introduces vulnerabilities (backdoors, hardcoded credentials, weakened crypto) disguised as legitimate code changes. |
| **Impact** | Production deployment of intentionally insecure code, potential data breach or unauthorized access to financial systems. |
| **Mitigating Controls** | • **SAST Scanner (Semgrep)** — detects injection flaws, hardcoded secrets, insecure patterns<br>• **Secrets Scanner (Gitleaks)** — blocks commits containing credentials<br>• **Policy Gate** — blocks builds with policy violations<br>• **Pre-commit hooks** — local detection before push<br>• **Code review requirements** — branch protection mandates peer review |
| **Residual Risk** | Sophisticated backdoors that don't match known vulnerability patterns will bypass SAST rules. Obfuscated malicious logic may pass review. No two-person rule is enforced at the tooling level for all code paths. |

#### T-IN-02: Credential Misuse

| Attribute | Detail |
|-----------|--------|
| **Description** | A developer with legitimate access misuses their credentials to access production systems, exfiltrate data, or grant unauthorized waivers to bypass security policies. |
| **Impact** | Policy bypass via fraudulent waivers, unauthorized access to production data, privilege escalation. |
| **Mitigating Controls** | • **Waiver workflow** — requires justification, designated approver, and expiration date<br>• **Audit trail** — records approver identity, justification, and waiver details<br>• **Team enforcement configuration** — limits waiver scope per team<br>• **Immutable evidence retention** — 2-year retention prevents evidence tampering |
| **Residual Risk** | Collusion between a developer and an approver can produce fraudulent waivers. No separation of duties is enforced beyond the approval field. Waiver approver identity is not verified against an authoritative list of approved approvers. |

#### T-IN-03: Social Engineering of Developers

| Attribute | Detail |
|-----------|--------|
| **Description** | An attacker uses social engineering to trick a developer into merging malicious PRs, installing compromised tools, or sharing credentials. |
| **Impact** | Introduction of malicious code or dependencies, credential compromise, pipeline manipulation. |
| **Mitigating Controls** | • **Multi-layer scanning** — even socially engineered code changes are scanned<br>• **Pre-commit hooks** — automatic local detection regardless of intent<br>• **Branch protection** — requires multiple reviewers, reducing single-point social engineering<br>• **Policy Gate** — automated enforcement independent of human judgment |
| **Residual Risk** | If social engineering convinces multiple reviewers to approve, the code merges and only automated scanning provides defense. Scanner rule coverage depends on known vulnerability patterns. |

---

### 2.4 External Adversaries Targeting the Service

#### T-EX-01: Injection Attacks (SQL, Command, Deserialization)

| Attribute | Detail |
|-----------|--------|
| **Description** | An external attacker exploits input validation flaws to execute arbitrary SQL queries, OS commands, or deserialized objects against the deployed application. |
| **Impact** | Data breach, unauthorized data modification, remote code execution on application servers. |
| **Mitigating Controls** | • **SAST Scanner (Semgrep)** — detects injection vulnerability patterns in source code<br>• **Policy Gate** — blocks deployment of code with critical injection findings<br>• **Red/Green demo** — validates that injection vulnerabilities are detected and blocked |
| **Residual Risk** | SAST tools have false negatives — complex injection paths or novel patterns may be missed. No DAST (Dynamic Application Security Testing) or runtime protection is included in the pipeline. |

#### T-EX-02: Credential Theft from Deployed Application

| Attribute | Detail |
|-----------|--------|
| **Description** | An attacker extracts hardcoded secrets, API keys, or database credentials from the deployed application through source code access, container image inspection, or memory dumps. |
| **Impact** | Unauthorized access to databases, third-party APIs, and internal services. Lateral movement within the infrastructure. |
| **Mitigating Controls** | • **Secrets Scanner (Gitleaks)** — prevents secrets from being committed to source<br>• **Pre-commit hooks** — blocks commits containing detected secrets<br>• **Container Scanner (Trivy image)** — detects secrets embedded in container layers<br>• **Policy Gate** — blocks builds with secret findings |
| **Residual Risk** | Secrets loaded at runtime from external secret managers are not scanned by the pipeline. Encrypted or obfuscated secrets in code may evade regex-based detection. |

#### T-EX-03: Infrastructure Compromise via IaC Misconfigurations

| Attribute | Detail |
|-----------|--------|
| **Description** | An attacker exploits misconfigured cloud infrastructure (public S3 buckets, open security groups, overly permissive IAM policies) to gain unauthorized access, exfiltrate data, or escalate privileges. |
| **Impact** | Data exposure from public storage, unauthorized network access, full AWS account compromise via wildcard IAM policies. |
| **Mitigating Controls** | • **IaC Scanner (Checkov)** — detects Terraform misconfigurations<br>• **OPA/Conftest policies** — enforce organization-specific rules (no public S3, no wildcard IAM, no open security groups, no unencrypted storage)<br>• **Policy Gate** — blocks deployment of non-compliant infrastructure<br>• **Red/Green demo** — validates IaC misconfiguration detection |
| **Residual Risk** | Runtime drift from IaC-defined state is not detected (no continuous compliance monitoring). Terraform resources not covered by existing Rego policies may have misconfigurations. Custom cloud services without Checkov rules are not scanned. |

#### T-EX-04: Container Image Exploitation

| Attribute | Detail |
|-----------|--------|
| **Description** | An attacker exploits vulnerabilities in the base container image or application dependencies within the running container to achieve code execution, privilege escalation, or container escape. |
| **Impact** | Container compromise, potential host escape, lateral movement to other containers or cloud resources. |
| **Mitigating Controls** | • **Container Scanner (Trivy image)** — detects known CVEs in base image and installed packages<br>• **Policy Gate (no_root_container)** — blocks containers running as root<br>• **Remediated Dockerfile** — uses minimal base image, non-root user, security best practices<br>• **Image Signing (cosign)** — ensures only verified images are deployed |
| **Residual Risk** | Zero-day container runtime vulnerabilities are not detected by scanning. Container escape via kernel exploits is outside pipeline control. No runtime container security monitoring (Falco, etc.) is included. |

---

## 3. Summary — Threat-to-Control Mapping

| Threat ID | Threat | Pipeline Layer / Control | Residual Risk Level |
|-----------|--------|--------------------------|---------------------|
| T-SC-01 | Malicious package injection | SCA (Trivy), SBOM (Syft), Policy Gate | **High** — zero-day packages undetected |
| T-SC-02 | Dependency confusion | SCA (Trivy), SBOM (Syft), pinned versions | **Medium** — no private registry enforcement |
| T-SC-03 | Compromised upstream repo | SCA (Trivy), SBOM (Syft), Provenance (cosign) | **High** — delayed CVE publication window |
| T-BE-01 | CI/CD pipeline tampering | Branch protection, Provenance (SLSA), Audit trail | **Medium** — admin bypass possible |
| T-BE-02 | Secrets exfiltration from CI | Keyless signing (OIDC), Gitleaks, secret scoping | **Medium** — network egress unrestricted |
| T-BE-03 | Unauthorized CI/CD access | Branch protection, Audit trail, Summary reports | **Medium** — no behavioral anomaly detection |
| T-IN-01 | Malicious developer code | SAST (Semgrep), Gitleaks, Policy Gate, Code review | **Medium** — sophisticated backdoors undetected |
| T-IN-02 | Credential misuse / waiver fraud | Waiver workflow, Audit trail, Evidence retention | **Medium** — no approver verification list |
| T-IN-03 | Social engineering | Multi-layer scanning, Pre-commit hooks, Branch protection | **Low** — automated scanning provides backstop |
| T-EX-01 | Injection attacks | SAST (Semgrep), Policy Gate | **Medium** — no DAST coverage |
| T-EX-02 | Credential theft | Gitleaks, Container scan (Trivy), Pre-commit hooks | **Low** — runtime secrets not in scope |
| T-EX-03 | IaC misconfigurations | IaC Scanner (Checkov), OPA policies, Policy Gate | **Medium** — no runtime drift detection |
| T-EX-04 | Container exploitation | Container scan (Trivy), no_root_container policy, cosign | **Medium** — zero-day / runtime gaps |

---

## 4. Residual Risk Summary

The following residual risks are not fully mitigated by the current pipeline configuration:

### High Residual Risk

| Risk | Why It Remains | Potential Impact |
|------|---------------|-----------------|
| Zero-day malicious packages | CVE databases lag behind actual compromises | Silent code execution in production |
| Upstream compromise window | Days-to-weeks gap between compromise and detection | Broad impact across all builds using the package |

### Medium Residual Risk

| Risk | Why It Remains | Potential Impact |
|------|---------------|-----------------|
| Admin bypass of branch protection | GitHub org admins can override rules | Pipeline controls circumvented |
| No DAST coverage | Pipeline is static-analysis only | Runtime injection paths missed |
| No runtime drift detection | IaC scanning only at build time | Production infra may deviate from code |
| Network egress from CI unrestricted | No outbound filtering on runners | Data exfiltration during builds |
| Sophisticated code backdoors | SAST pattern matching has limits | Intentional vulnerabilities merged |
| No approver verification for waivers | Approver field is free-text | Fraudulent waivers possible |

### Low Residual Risk

| Risk | Why It Remains | Potential Impact |
|------|---------------|-----------------|
| Runtime secrets not scanned | Pipeline scans source/images only | Secrets in env vars or vaults not validated |
| Social engineering with multiple colluders | Requires multiple compromised reviewers | Low probability but high impact |

---

## 5. Recommendations for Further Hardening

### Priority 1 — High Impact, Achievable Short-Term

1. **Private registry enforcement** — Configure pip to resolve internal packages from a private registry before falling back to PyPI, mitigating dependency confusion (T-SC-02).
2. **Restrict CI network egress** — Use GitHub Actions IP allowlists or self-hosted runners with outbound firewall rules to prevent exfiltration (T-BE-02).
3. **Waiver approver verification** — Validate the `approver` field against a configured list of authorized approvers per policy (T-IN-02).

### Priority 2 — Medium Impact, Medium Effort

4. **Add DAST scanning** — Integrate a dynamic application security testing tool (e.g., OWASP ZAP) to catch runtime injection paths not visible to SAST (T-EX-01).
5. **Runtime drift detection** — Deploy a tool like AWS Config Rules or Terraform Cloud drift detection to identify infrastructure changes made outside IaC (T-EX-03).
6. **Behavioral anomaly detection for CI** — Monitor for unusual pipeline patterns (off-hours runs, unexpected repos, high-frequency builds) that may indicate compromised accounts (T-BE-03).

### Priority 3 — Strategic, Longer-Term

7. **Source-level package verification** — Adopt Sigstore/TUF for Python package provenance verification once ecosystem support matures (T-SC-01, T-SC-03).
8. **Runtime container security** — Deploy Falco or similar eBPF-based runtime monitoring to detect container escapes and anomalous behavior (T-EX-04).
9. **Two-person integrity for critical paths** — Implement cryptographic two-person approval for workflow changes and production deployments (T-BE-01, T-IN-01).
10. **Secret rotation automation** — Integrate with a secrets manager (AWS Secrets Manager, HashiCorp Vault) with automatic rotation to limit the window of stolen credential usefulness (T-EX-02).

---

## 6. Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2025-01-01 | Security Architecture Team | Initial threat model creation |

---

*This threat model should be reviewed and updated quarterly, or whenever significant changes are made to the pipeline architecture, tooling, or threat landscape.*
