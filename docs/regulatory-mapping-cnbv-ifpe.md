# Regulatory Mapping — CNBV/IFPE

## 1. Introduction

This document maps the Secure Software Factory pipeline controls to the regulatory requirements of Mexico's **Comisión Nacional Bancaria y de Valores (CNBV)** for **Instituciones de Fondos de Pago Electrónico (IFPE)** authorization, governed under the Ley Fintech and its secondary regulations.

The organization is pursuing IFPE authorization under Banxico/CNBV oversight. This mapping demonstrates how the automated CI/CD security pipeline provides continuous evidence of compliance with operational security, information protection, and technology risk management requirements established in the IFPE regulatory framework.

### Organization Context

| Attribute | Detail |
|-----------|--------|
| Entity Type | IFPE (Electronic Payment Fund Institution) |
| Regulator | CNBV / Banxico |
| Legal Framework | Ley para Regular las Instituciones de Tecnología Financiera (Ley Fintech) |
| Key Articles | Art. 56–58, Disposiciones de carácter general aplicables a las ITF |
| Corridor | Mexico–US treasury and FX operations |
| Engineering Scale | ~25 engineers, 5 SWAT teams, Lead Time < 1h |

---

## 2. Pipeline Control to IFPE Requirement Mapping

### 2.1 Master Mapping Table

| Pipeline Control | Tool | IFPE Requirement | Article/Disposition | Evidence Artifact |
|------------------|------|------------------|---------------------|-------------------|
| Secrets Scanning | Gitleaks | Protection of access credentials and cryptographic keys | Art. 58 – Seguridad de la Información | SARIF report (`gitleaks-results.sarif`) |
| Static Analysis (SAST) | Semgrep | Secure software development practices | Art. 58 – Seguridad de la Información | SARIF report (`semgrep-results.sarif`) |
| Dependency Analysis (SCA) | Trivy (fs) | Third-party component risk management | Art. 58 – Riesgo Operacional | SARIF report (`trivy-fs-results.sarif`) |
| Infrastructure-as-Code Scanning | Checkov | Secure infrastructure configuration | Art. 58 – Riesgo Operacional | SARIF report (`checkov-results.sarif`) |
| Container Scanning | Trivy (image) | Secure runtime environment | Art. 58 – Riesgo Operacional | SARIF report (`trivy-image-results.sarif`) |
| Policy-as-Code Gate | OPA/Conftest | Automated compliance enforcement | Art. 58 – Control Interno | Policy decision record (JSON) |
| SBOM Generation | Syft | Asset inventory and dependency transparency | Art. 56 – Continuidad Operativa | SBOM (SPDX 2.3 JSON) |
| Image Signing | cosign | Integrity verification of deployed artifacts | Art. 58 – Seguridad de la Información | Signed image digest + provenance attestation |
| Provenance Attestation | cosign/SLSA | Traceability of software origin and build process | Art. 58 – Seguridad de la Información | SLSA provenance document |
| Waiver Workflow | Custom (Python) | Documented exceptions with approval and expiration | Art. 58 – Control Interno | Waiver JSON + audit trail record |
| Audit Trail | Custom (Python) | Immutable evidence retention for regulatory review | Art. 58 – Control Interno | Per-run summary report (JSON) |
| Pre-commit Hooks | Gitleaks + Semgrep | Shift-left security controls at developer level | Art. 58 – Seguridad de la Información | Local commit blocking (no artifact) |
| Phased Enforcement | Custom (Python) | Risk-proportional control adoption | Art. 56 – Gestión de Riesgos | Team configuration + notification records |

---

## 3. IFPE Article Breakdown

### 3.1 Artículo 56 — Continuidad Operativa y Gestión de Riesgos

| Obligation | Pipeline Control | How It's Satisfied |
|------------|------------------|-------------------|
| Maintain operational continuity plans | SBOM Generation (Syft) | Complete dependency inventory enables rapid incident response when upstream packages are compromised |
| Risk management framework | Phased Enforcement | Gradual rollout allows risk-proportional adoption without disrupting deployment velocity |
| Technology risk identification | All scanning layers | Multi-layer defense-in-depth identifies risks across code, dependencies, infrastructure, and containers |
| Business continuity documentation | Per-run summary reports | Immutable records prove security posture at any point in time for continuity audits |

### 3.2 Artículo 58 — Seguridad de la Información

#### IFPE-ART58-SEC (Security Controls)

| Obligation | Pipeline Control | Evidence Produced |
|------------|------------------|-------------------|
| Protect confidential information and access credentials | Gitleaks (secrets scanning) | SARIF report showing no committed secrets; pre-commit hooks block secrets before push |
| Secure software development lifecycle | Semgrep (SAST) | SARIF report identifying code vulnerabilities; policy gate blocks insecure code |
| Cryptographic integrity of deployed systems | cosign (image signing) | Signed image digests with SLSA provenance proving artifact integrity and origin |
| Encryption of sensitive data at rest | Checkov + OPA policy (`no_unencrypted_storage`) | Policy decision blocking unencrypted S3 buckets |
| Access control enforcement | OPA policy (`no_wildcard_iam`) | Policy decision blocking overly permissive IAM policies |

#### IFPE-ART58-OPS (Operational Security)

| Obligation | Pipeline Control | Evidence Produced |
|------------|------------------|-------------------|
| Vulnerability management program | Trivy (SCA + container scan) | SARIF reports with CVE findings; policy gate enforces remediation |
| Secure infrastructure configuration | Checkov (IaC scanning) | SARIF report detecting Terraform misconfigurations |
| Patch management for third-party components | Trivy (SCA) | Dependency CVE scanning per pipeline run; SBOM tracks all versions |
| Least-privilege access principles | OPA policies (`no_wildcard_iam`, `no_open_security_group`) | Policy decisions blocking wildcard IAM and open network access |
| Runtime environment hardening | Trivy (container) + OPA (`no_root_container`) | Container vulnerability report; policy blocking root containers |

#### IFPE-ART58-CI (Control Interno)

| Obligation | Pipeline Control | Evidence Produced |
|------------|------------------|-------------------|
| Automated compliance verification | Policy-as-Code Gate (OPA/Conftest) | Policy decision records with pass/fail and violation details |
| Documented exceptions and approvals | Waiver Workflow | Waiver JSON with justification, approver, expiration, and linked violation |
| Immutable audit trail | Audit Trail module | Per-run summary, policy decisions, and waiver records retained for 2 years |
| Segregation of duties in change management | Branch protection + code review + policy gate | Automated enforcement independent of individual developers |
| Evidence of control effectiveness | Red/Green Demonstrations | Red-demo proves controls block insecure code; green-demo proves secure path works |

---

## 4. Coverage per Scanning Layer

### 4.1 Gitleaks — Secrets Scanning

| IFPE Reference | Control Objective | Coverage |
|----------------|-------------------|----------|
| IFPE-ART58-SEC | Protect credentials from exposure | ✅ Detects API keys, private keys, AWS credentials in source code and git history |
| IFPE-ART58-SEC | Prevention of unauthorized access | ✅ Pre-commit hooks block secrets before they enter the repository |
| IFPE-ART58-CI | Evidence of credential hygiene | ✅ SARIF reports document scanning results per pipeline run |

**Evidence Artifacts:**
- `gitleaks-results.sarif` — SARIF 2.1.0 report with detected secret locations
- Pre-commit hook logs (local enforcement)
- Regulatory tags: `IFPE-ART58-SEC`

### 4.2 Semgrep — Static Application Security Testing (SAST)

| IFPE Reference | Control Objective | Coverage |
|----------------|-------------------|----------|
| IFPE-ART58-SEC | Secure software development | ✅ Detects SQL injection, command injection, insecure deserialization patterns |
| IFPE-ART58-SEC | Input validation enforcement | ✅ Identifies code paths lacking input sanitization |
| IFPE-ART58-CI | Development security controls | ✅ Policy gate blocks builds with critical SAST findings |

**Evidence Artifacts:**
- `semgrep-results.sarif` — SARIF 2.1.0 report with vulnerability locations and rule descriptions
- Regulatory tags: `IFPE-ART58-SEC`

### 4.3 Trivy (fs) — Software Composition Analysis (SCA)

| IFPE Reference | Control Objective | Coverage |
|----------------|-------------------|----------|
| IFPE-ART58-OPS | Vulnerability management | ✅ Identifies known CVEs in all third-party dependencies |
| IFPE-ART58-OPS | Patch management | ✅ Flags outdated or vulnerable dependency versions |
| Art. 56 | Technology risk identification | ✅ Provides risk-scored dependency findings for prioritization |

**Evidence Artifacts:**
- `trivy-fs-results.sarif` — SARIF 2.1.0 report with CVE details, affected packages, and severity
- Regulatory tags: `IFPE-ART58-OPS`

### 4.4 Checkov — Infrastructure-as-Code Scanning

| IFPE Reference | Control Objective | Coverage |
|----------------|-------------------|----------|
| IFPE-ART58-OPS | Secure infrastructure configuration | ✅ Detects Terraform misconfigurations before deployment |
| IFPE-ART58-OPS | Least-privilege enforcement | ✅ Checks IAM policies, security groups, storage encryption |
| IFPE-ART58-CI | Automated compliance verification | ✅ Custom Checkov checks enforce organization-specific policies |

**Evidence Artifacts:**
- `checkov-results.sarif` — SARIF 2.1.0 report with failed Checkov checks and affected resources
- Regulatory tags: `IFPE-ART58-OPS`

### 4.5 Trivy (image) — Container Scanning

| IFPE Reference | Control Objective | Coverage |
|----------------|-------------------|----------|
| IFPE-ART58-OPS | Runtime environment security | ✅ Scans container images for OS and application CVEs |
| IFPE-ART58-OPS | Configuration hardening | ✅ Detects root user, exposed ports, insecure configurations |
| IFPE-ART58-SEC | Integrity of deployed systems | ✅ Ensures only scanned, signed images reach production |

**Evidence Artifacts:**
- `trivy-image-results.sarif` — SARIF 2.1.0 report with image vulnerability findings
- Regulatory tags: `IFPE-ART58-OPS`

### 4.6 cosign — Image Signing and Provenance

| IFPE Reference | Control Objective | Coverage |
|----------------|-------------------|----------|
| IFPE-ART58-SEC | Cryptographic integrity verification | ✅ Keyless signing via GitHub OIDC proves image authenticity |
| IFPE-ART58-SEC | Traceability of build origin | ✅ SLSA provenance attestation links image to source commit and workflow |
| IFPE-ART58-CI | Non-repudiation of deployments | ✅ Signed attestations provide cryptographic proof of pipeline execution |

**Evidence Artifacts:**
- Signed image digest (SHA-256)
- SLSA provenance attestation (JSON)
- Signature stored in container registry alongside image
- Regulatory tags: `IFPE-ART58-SEC`

### 4.7 Syft — SBOM Generation

| IFPE Reference | Control Objective | Coverage |
|----------------|-------------------|----------|
| Art. 56 | Asset inventory and dependency transparency | ✅ Complete listing of all OS packages and application dependencies |
| IFPE-ART58-OPS | Vulnerability tracking across supply chain | ✅ SBOM enables cross-referencing against future CVE disclosures |
| IFPE-ART58-CI | Audit readiness | ✅ SBOM stored as immutable build artifact for 2-year retention |

**Evidence Artifacts:**
- SBOM (SPDX 2.3 JSON format)
- Regulatory tags: `IFPE-ART58-OPS`

---

## 5. Evidence Artifacts for IFPE Authorization

### 5.1 Artifact Inventory

| Artifact | Format | Retention | IFPE Purpose |
|----------|--------|-----------|--------------|
| SARIF Reports (per scanner) | SARIF 2.1.0 JSON | 2 years | Demonstrate continuous vulnerability scanning |
| Aggregated SARIF Report | SARIF 2.1.0 JSON | 2 years | Unified view with regulatory metadata tags |
| Policy Decision Records | JSON | 2 years | Prove policy enforcement and exception handling |
| Waiver Records | JSON | 2 years | Document justified exceptions with approval chain |
| Audit Trail Records | JSON | 2 years | Immutable evidence of all security decisions |
| Per-run Summary Reports | JSON | 2 years | Complete pipeline execution record per commit |
| SBOM | SPDX 2.3 JSON | 2 years | Dependency inventory for supply-chain audits |
| Signed Image + Attestation | OCI registry + JSON | 2 years | Cryptographic proof of artifact integrity |
| Red/Green Demo Reports | JSON | 2 years | Evidence that controls are effective |
| Team Configuration | JSON | Active | Demonstrate gradual, risk-proportional rollout |

### 5.2 How to Present Evidence to CNBV

During the IFPE authorization process and subsequent audits, present evidence as follows:

1. **Initial Authorization** — Provide Red/Green demo reports proving pipeline effectiveness, ADRs justifying tool selection, and this regulatory mapping document.
2. **Periodic Reviews** — Export per-run summary reports for the review period showing continuous compliance. SBOM and SARIF archives demonstrate ongoing vulnerability management.
3. **Incident Response** — Use SBOM and provenance attestations to trace affected deployments. Audit trail records show the security posture at the time of deployment.
4. **Exception Handling** — Present waiver records with justification, approver, and expiration for any policy exceptions.

---

## 6. Organization-Specific Context for IFPE Authorization

### 6.1 Why This Pipeline Supports IFPE Authorization

CNBV requires IFPEs to demonstrate:

| CNBV Expectation | How the Pipeline Addresses It |
|------------------|-------------------------------|
| Robust technology risk management | Multi-layer scanning identifies risks across code, dependencies, infrastructure, and runtime |
| Secure software development practices | SAST + secrets scanning + policy gates enforce secure coding standards automatically |
| Protection of user funds and data | Encryption enforcement, least-privilege IAM, and network security policies prevent exposure |
| Operational continuity safeguards | SBOM enables rapid incident response; immutable evidence supports forensic reconstruction |
| Internal control framework | Policy-as-code gates, waiver workflows, and audit trails provide automated control evidence |
| Evidence retention for regulatory review | 2-year immutable artifact retention exceeds typical audit lookback periods |

### 6.2 Continuous Compliance Model

Unlike point-in-time audits, this pipeline provides **continuous compliance evidence**:

- Every commit triggers a full security assessment
- Policy decisions are recorded automatically with regulatory references
- Evidence accumulates immutably over time
- Teams adopt controls gradually without disrupting the organization's < 1h lead time

### 6.3 Limitations and Complementary Controls

This pipeline does NOT replace:

| Area | Not Covered | Complementary Control Needed |
|------|-------------|------------------------------|
| Runtime security | No WAF, RASP, or runtime monitoring | Deploy runtime protection (WAF, API gateway) |
| Network security | No VPC, firewall, or DDoS mitigation scanning | Separate network security assessment |
| Physical security | No physical access controls | Data center / cloud provider certifications |
| Business logic | Only pattern-based detection | Manual penetration testing and code review |
| Privacy / data residency | No PII detection or data flow mapping | Separate ARCO/data protection assessment |

---

## 7. Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2025-01-01 | Compliance Engineering Team | Initial regulatory mapping creation |

---

*This document should be updated when pipeline controls change, new CNBV dispositions are published, or during IFPE authorization review cycles.*
