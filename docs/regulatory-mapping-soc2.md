# Regulatory Mapping — SOC 2 Trust Services Criteria

## 1. Introduction

This document maps the Secure Software Factory pipeline controls to the **SOC 2 Type II Trust Services Criteria (TSC)** as defined by the AICPA. The mapping demonstrates how the automated CI/CD security pipeline provides continuous evidence supporting SOC 2 audit readiness across the Security, Availability, and Processing Integrity categories.

### SOC 2 Context for the organization

| Attribute | Detail |
|-----------|--------|
| Report Type | SOC 2 Type II |
| Trust Categories In Scope | Security (Common Criteria), Availability, Processing Integrity |
| Audit Period | Continuous (pipeline runs per commit) |
| Engineering Scale | ~25 engineers, 5 SWAT teams, Lead Time < 1h |
| Service Description | Treasury and FX platform operating in Mexico–US corridor |

---

## 2. Pipeline Control to SOC 2 TSC Mapping

### 2.1 Master Mapping Table

| Pipeline Control | Tool | SOC 2 TSC | Criteria Description | Evidence Artifact |
|------------------|------|-----------|---------------------|-------------------|
| Secrets Scanning | Gitleaks | CC6.1 | Logical and Physical Access Controls | `gitleaks-results.sarif` |
| SAST Scanning | Semgrep | CC6.6 | Security measures against threats outside system boundaries | `semgrep-results.sarif` |
| SCA Scanning | Trivy (fs) | CC7.1 | Detection of changes that could impact security | `trivy-fs-results.sarif` |
| IaC Scanning | Checkov | CC6.1 | Logical and Physical Access Controls | `checkov-results.sarif` |
| Container Scanning | Trivy (image) | CC7.1 | Detection of changes that could impact security | `trivy-image-results.sarif` |
| Policy-as-Code Gate | OPA/Conftest | CC8.1 | Authorization and approval of changes | Policy decision record (JSON) |
| SBOM Generation | Syft | CC6.1, CC7.2 | Asset management and incident response | SBOM (SPDX 2.3 JSON) |
| Image Signing | cosign | CC6.1, CC8.1 | Integrity and authorization of deployed artifacts | Signed image + provenance |
| Provenance Attestation | cosign/SLSA | CC8.1 | Traceability of changes through lifecycle | SLSA provenance document |
| Waiver Workflow | Custom (Python) | CC6.2 | Registration and authorization of users/exceptions | Waiver JSON + audit trail |
| Audit Trail | Custom (Python) | CC7.2, CC7.3 | Monitoring and evaluation of system components | Per-run summary report (JSON) |
| Pre-commit Hooks | Gitleaks + Semgrep | CC6.6 | Prevent unauthorized changes before they enter systems | Local commit blocking |
| Phased Enforcement | Custom (Python) | CC1.4 | Board of directors oversight / management review | Team config + notifications |
| Red/Green Demos | Pipeline workflows | CC4.1, CC4.2 | Monitoring and evaluation of controls | Demo reports (JSON) |

---

## 3. Trust Services Criteria Breakdown

### 3.1 CC6 — Logical and Physical Access Controls

#### CC6.1 — Logical Access Security

*The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.*

| Pipeline Control | How It Satisfies CC6.1 |
|------------------|------------------------|
| Gitleaks (secrets scanning) | Prevents credentials from being committed to source code, reducing the risk of unauthorized access through leaked secrets |
| Checkov (IaC scanning) | Enforces least-privilege IAM policies and private network configurations in infrastructure definitions |
| OPA policy: `no_wildcard_iam` | Blocks IAM policies with `Action: *`, ensuring least-privilege access |
| OPA policy: `no_open_security_group` | Blocks security groups open to 0.0.0.0/0, preventing unauthorized network access |
| OPA policy: `no_unencrypted_storage` | Requires encryption at rest for all storage resources |
| cosign (image signing) | Ensures only authorized, verified images are deployed to production |
| Syft (SBOM) | Provides complete asset inventory of all software components |

**Evidence Artifacts:**
- SARIF reports from Gitleaks and Checkov
- Policy decision records showing IAM, network, and encryption enforcement
- SBOM as dependency inventory
- Signed image digests

#### CC6.2 — Registration and Authorization of Users

*Prior to issuing system credentials and granting access, the entity registers and authorizes new internal and external users.*

| Pipeline Control | How It Satisfies CC6.2 |
|------------------|------------------------|
| Waiver Workflow | Requires designated approver, justification, and expiration for any policy exception — modeling the access exception process |
| Team Configuration | Per-team enforcement levels demonstrate controlled access to pipeline capabilities |
| Branch Protection (referenced) | Code changes require authorized reviewers before merge |

**Evidence Artifacts:**
- Waiver records with approver identity and justification
- Team configuration files showing access levels
- Audit trail records of all exceptions granted

#### CC6.6 — Measures Against Threats Outside System Boundaries

*The entity implements measures to prevent or detect and act upon the introduction of unauthorized or malicious software.*

| Pipeline Control | How It Satisfies CC6.6 |
|------------------|------------------------|
| Semgrep (SAST) | Detects code-level vulnerabilities (injection, deserialization) that could be exploited by external attackers |
| Pre-commit hooks | Block malicious patterns before they enter the repository |
| Policy Gate | Blocks deployment of code with security vulnerabilities |
| Trivy (SCA) | Identifies malicious or vulnerable third-party dependencies |

**Evidence Artifacts:**
- SARIF reports from Semgrep showing detected vulnerability patterns
- Policy decision records blocking vulnerable code
- Regulatory tags: `SOC2-CC6.6`

---

### 3.2 CC7 — System Operations

#### CC7.1 — Detection of Changes

*To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities, and susceptibilities to newly discovered vulnerabilities.*

| Pipeline Control | How It Satisfies CC7.1 |
|------------------|------------------------|
| Trivy (SCA - filesystem) | Detects newly disclosed CVEs in application dependencies on every commit |
| Trivy (container image) | Identifies vulnerabilities introduced through base image updates or new packages |
| Pipeline trigger on push | Every code change is automatically scanned — no manual intervention required |
| Aggregated SARIF with regulatory tags | Changes in vulnerability posture are tagged and tracked over time |

**Evidence Artifacts:**
- SARIF reports from Trivy (fs and image) with CVE details
- Per-run summary reports showing finding counts over time
- Regulatory tags: `SOC2-CC7.1`

#### CC7.2 — Monitoring System Components

*The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives.*

| Pipeline Control | How It Satisfies CC7.2 |
|------------------|------------------------|
| Audit Trail | Records all security decisions, providing a monitoring baseline for anomaly detection |
| Per-run Summary Reports | Aggregate view of pipeline health; deviations from normal patterns are visible |
| SBOM (Syft) | Enables detection of unexpected dependency additions (potential supply-chain attacks) |
| Policy Decision Records | Track pass/fail rates to identify unusual patterns |

**Evidence Artifacts:**
- Audit trail JSON records
- Per-run summary reports linking commit SHA to all findings
- SBOM diffs between builds (enabled by artifact retention)

#### CC7.3 — Evaluation of Detected Events

*The entity evaluates anomalies to determine whether they represent security events.*

| Pipeline Control | How It Satisfies CC7.3 |
|------------------|------------------------|
| Policy Gate (OPA/Conftest) | Automatically evaluates scan findings against security policies — categorizing them as violations or acceptable |
| Waiver Workflow | Provides a formal process to evaluate whether detected events require exception handling |
| Severity Classification | Policy violations include severity levels (critical, high, medium, low) for prioritization |

**Evidence Artifacts:**
- Policy decision records with severity-classified violations
- Waiver records documenting exception evaluations
- Red/Green demo reports proving evaluation accuracy

---

### 3.3 CC8 — Change Management

#### CC8.1 — Authorization and Approval of Changes

*The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure and software.*

| Pipeline Control | How It Satisfies CC8.1 |
|------------------|------------------------|
| Policy-as-Code Gate | Automated approval/rejection of changes based on security policy compliance |
| cosign (image signing) | Only pipeline-built images receive a signature — unauthorized builds cannot produce signed artifacts |
| Provenance Attestation (SLSA) | Documents the exact workflow, source repo, and commit that produced each artifact |
| Phased Enforcement | Demonstrates controlled rollout of changes to security controls |
| Waiver Workflow | Documented approval process for policy exceptions |

**Evidence Artifacts:**
- Policy decision records (automated approval/rejection)
- Signed image digests proving authorized build origin
- SLSA provenance linking artifact to source
- Team enforcement transition records

---

### 3.4 CC4 — Monitoring Activities

#### CC4.1 — Ongoing and Separate Evaluations

*The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.*

| Pipeline Control | How It Satisfies CC4.1 |
|------------------|------------------------|
| Red/Green Demonstrations | Prove pipeline controls are effective — red-demo shows blocking, green-demo shows compliant path |
| Continuous pipeline execution | Every commit triggers evaluation — controls are tested in real-time, not periodically |
| Property-based tests | Verify correctness of policy logic across hundreds of generated inputs |

**Evidence Artifacts:**
- Red-demo and green-demo workflow reports
- Test execution results (unit + property tests)
- Pipeline run history demonstrating continuous evaluation

#### CC4.2 — Communication of Deficiencies

*The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for corrective action.*

| Pipeline Control | How It Satisfies CC4.2 |
|------------------|------------------------|
| Policy Gate failure notifications | Build blocks notify developers immediately upon policy violations |
| Phased enforcement notifications | Teams receive 5 business days notice before enforcement transitions |
| Per-run summary reports | Provide visibility into security posture per team |

**Evidence Artifacts:**
- Build failure logs with human-readable violation explanations
- Notification records for enforcement transitions
- Team dashboard data (violation trends and remediation guidance)

---

### 3.5 CC1 — Control Environment

#### CC1.4 — Demonstrates Commitment to Competence

*The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives.*

| Pipeline Control | How It Satisfies CC1.4 |
|------------------|------------------------|
| Phased Enforcement | Gradual rollout allows teams to learn security practices without disruption |
| Pre-commit hooks | Provide immediate educational feedback to developers at their workstation |
| Developer dashboard | Shows remediation guidance helping engineers build security competence |
| ADRs | Document rationale, enabling engineers to understand security decisions |

**Evidence Artifacts:**
- Team configuration showing progression from warning to enforcing mode
- ADR documentation demonstrating technical decision-making process
- Rollout timeline and notification records

---

## 4. Coverage per Scanning Layer

### 4.1 Gitleaks — Secrets Scanning

| SOC 2 TSC | Criteria | How Satisfied |
|-----------|----------|---------------|
| CC6.1 | Logical access controls | Prevents credential leakage that could enable unauthorized access |
| CC6.6 | Threat prevention | Blocks secrets before they reach shared repositories |
| CC8.1 | Change authorization | Ensures only credential-free code is approved for deployment |

### 4.2 Semgrep — SAST

| SOC 2 TSC | Criteria | How Satisfied |
|-----------|----------|---------------|
| CC6.6 | Threat prevention | Detects code vulnerabilities (injection, insecure patterns) that external attackers could exploit |
| CC8.1 | Change authorization | Blocks vulnerable code from progressing through the pipeline |
| CC7.1 | Change detection | Identifies when code changes introduce new vulnerability patterns |

### 4.3 Trivy (fs) — SCA

| SOC 2 TSC | Criteria | How Satisfied |
|-----------|----------|---------------|
| CC7.1 | Change detection | Detects newly disclosed CVEs in third-party dependencies |
| CC6.6 | Threat prevention | Blocks dependencies with known malicious or vulnerable code |
| CC4.1 | Ongoing evaluation | Continuous scanning catches vulnerabilities as CVE databases update |

### 4.4 Checkov — IaC Scanning

| SOC 2 TSC | Criteria | How Satisfied |
|-----------|----------|---------------|
| CC6.1 | Logical access controls | Enforces least-privilege IAM, private networks, encrypted storage |
| CC8.1 | Change authorization | Blocks infrastructure changes that violate security policies |
| CC7.1 | Change detection | Detects when IaC changes weaken security posture |

### 4.5 Trivy (image) — Container Scanning

| SOC 2 TSC | Criteria | How Satisfied |
|-----------|----------|---------------|
| CC7.1 | Change detection | Identifies vulnerabilities in container base images and packages |
| CC6.1 | Logical access controls | Detects containers running as root (privilege escalation risk) |
| CC6.6 | Threat prevention | Blocks deployment of vulnerable container images |

### 4.6 cosign — Image Signing and Provenance

| SOC 2 TSC | Criteria | How Satisfied |
|-----------|----------|---------------|
| CC6.1 | Logical access controls | Only pipeline-produced images are signed — prevents deployment of unauthorized artifacts |
| CC8.1 | Change authorization | Signature proves the artifact was produced by an authorized build process |
| CC7.2 | Monitoring | Unsigned images in production indicate unauthorized changes |

### 4.7 Syft — SBOM Generation

| SOC 2 TSC | Criteria | How Satisfied |
|-----------|----------|---------------|
| CC6.1 | Asset management | Complete inventory of all software components in deployed artifacts |
| CC7.1 | Change detection | SBOM diffs between builds reveal unexpected dependency changes |
| CC7.2 | Monitoring | Enables ongoing tracking of supply-chain composition |

---

## 5. Evidence Artifacts for SOC 2 Auditors

### 5.1 Artifact-to-Criteria Matrix

| Evidence Artifact | Format | Retention | TSC Supported | Auditor Use Case |
|-------------------|--------|-----------|---------------|------------------|
| SARIF Reports (per scanner) | SARIF 2.1.0 JSON | 2 years | CC6.1, CC6.6, CC7.1 | Prove continuous vulnerability scanning occurs |
| Aggregated SARIF (with reg. tags) | SARIF 2.1.0 JSON | 2 years | CC7.1, CC7.2 | Unified view of all findings with regulatory classification |
| Policy Decision Records | JSON | 2 years | CC8.1, CC7.3 | Prove automated enforcement of security policies |
| Waiver Records | JSON | 2 years | CC6.2, CC7.3 | Document controlled exceptions with approval chain |
| Audit Trail Records | JSON | 2 years | CC7.2, CC7.3 | Immutable record of all security decisions |
| Per-run Summary Reports | JSON | 2 years | CC4.1, CC7.2 | Per-commit security posture for any point-in-time query |
| SBOM | SPDX 2.3 JSON | 2 years | CC6.1, CC7.1 | Dependency inventory for supply-chain audit |
| Signed Image + Provenance | OCI + JSON | 2 years | CC6.1, CC8.1 | Cryptographic proof of authorized build origin |
| Red/Green Demo Reports | JSON | 2 years | CC4.1, CC4.2 | Control effectiveness demonstration |
| Team Configuration | JSON | Active | CC1.4, CC8.1 | Phased rollout documentation |
| Property Test Results | pytest output | Per run | CC4.1 | Prove policy logic correctness |

### 5.2 Presenting Evidence to Auditors

**For SOC 2 Type II examination:**

1. **Control Design** — Present this mapping document, ADRs, and the threat model to demonstrate control design intent.
2. **Operating Effectiveness** — Export per-run summary reports for the audit period (typically 6–12 months) showing continuous pipeline execution and policy enforcement.
3. **Exception Management** — Provide waiver records with justification, approver, and expiration for all exceptions during the audit period.
4. **Control Testing** — Reference Red/Green demo results and property-based test execution as evidence of ongoing control validation.
5. **Incident Analysis** — Use SBOM and provenance attestations to demonstrate traceability during any incident investigation.

---

## 6. Gap Analysis — Controls Not Covered by the Pipeline

### 6.1 SOC 2 Criteria Requiring Complementary Controls

| SOC 2 TSC | Criteria | Gap | Required Complementary Control |
|-----------|----------|-----|-------------------------------|
| CC6.3 | Removal of access rights | Pipeline does not manage user provisioning/deprovisioning | IAM lifecycle management (Okta, Azure AD) |
| CC6.4 | Access restrictions on physical assets | Pipeline operates in cloud; no physical access controls | Cloud provider SOC 2 report (AWS, GCP) |
| CC6.5 | Disposal of confidential data | Pipeline does not manage data destruction | Data retention and destruction policies |
| CC6.7 | Restriction of data transmission | Pipeline does not enforce network encryption in transit | TLS/mTLS configuration, API gateway policies |
| CC6.8 | Prevention of threats from software flaws | No DAST or runtime protection | WAF, RASP, or DAST tool integration |
| CC7.4 | Incident response | Pipeline detects but does not orchestrate incident response | Incident response runbooks, PagerDuty/Opsgenie |
| CC7.5 | Recovery from identified events | Pipeline does not handle rollback or recovery | Blue/green deployment, automated rollback |
| CC9.1 | Risk mitigation selection | Pipeline implements chosen controls but does not perform risk assessment | Enterprise risk management process |
| CC9.2 | Risk acceptance | Waivers partially address this; no formal risk acceptance board | Risk committee with documented acceptance criteria |
| A1.1 | Recovery objectives | Pipeline does not manage RTO/RPO | Disaster recovery plan and testing |
| A1.2 | Environmental protections | Not applicable to CI/CD pipeline | Cloud provider environmental controls |

### 6.2 Gap Prioritization

| Priority | Gap | Impact on SOC 2 Readiness | Recommended Action |
|----------|-----|---------------------------|-------------------|
| High | No DAST coverage (CC6.8) | Auditor may question completeness of vulnerability detection | Add OWASP ZAP or similar DAST tool |
| High | No incident response orchestration (CC7.4) | Needed for Security criteria | Implement IR runbooks linked to pipeline alerts |
| Medium | No access lifecycle management (CC6.3) | Required for complete access control narrative | Integrate with identity provider |
| Medium | No automated rollback (CC7.5) | Recovery from security incidents is manual | Add deployment rollback automation |
| Low | No formal risk acceptance board (CC9.2) | Waiver workflow partially addresses this | Formalize risk acceptance committee |
| Low | No data transmission controls (CC6.7) | Network-level, outside pipeline scope | Separate network security controls |

### 6.3 Coverage Summary

```
SOC 2 Trust Services Criteria Coverage:

CC1 (Control Environment):        ██████████░░  ~80% (CC1.4 covered, CC1.1-CC1.3 organizational)
CC2 (Communication):              ████░░░░░░░░  ~35% (pipeline notifications partially cover)
CC3 (Risk Assessment):            ██████░░░░░░  ~50% (threat model, but no formal risk register)
CC4 (Monitoring):                 ████████████  ~95% (strong via continuous pipeline + demos)
CC5 (Control Activities):         ████████░░░░  ~70% (automated but some manual processes needed)
CC6 (Logical/Physical Access):    ████████░░░░  ~65% (strong on logical, gaps on physical/lifecycle)
CC7 (System Operations):          ██████████░░  ~80% (detection strong, response/recovery gaps)
CC8 (Change Management):          ████████████  ~95% (comprehensive via policy gate + signing)
CC9 (Risk Mitigation):            ██████░░░░░░  ~50% (implementation strong, governance gaps)
A1 (Availability):                ████░░░░░░░░  ~30% (outside primary pipeline scope)
```

---

## 7. Continuous Compliance Evidence Model

### 7.1 How the Pipeline Supports Type II Examination

SOC 2 Type II requires evidence that controls operated effectively **over a period of time**. The pipeline provides this through:

| Type II Requirement | Pipeline Evidence |
|--------------------|-------------------|
| Controls operated consistently | Per-run summary reports for every commit during audit period |
| Exceptions were properly managed | Waiver records with approval, justification, and expiration |
| Monitoring was ongoing | Continuous pipeline trigger on every push; no gaps in scanning |
| Changes were authorized | Policy decision records and signed image provenance |
| Deficiencies were communicated | Build failure notifications and enforcement transition alerts |

### 7.2 Audit Period Evidence Extraction

To prepare for a SOC 2 Type II audit covering a specific period:

1. Export all per-run summary reports for the audit window
2. Compile waiver records granted during the period
3. Generate finding trend analysis (aggregate SARIF counts over time)
4. Provide Red/Green demo execution from within the audit period
5. Export team enforcement transitions and notifications
6. Reference signed image provenance for all production deployments

---

## 8. Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2025-01-01 | Compliance Engineering Team | Initial SOC 2 regulatory mapping creation |

---

*This document should be updated when pipeline controls change, TSC interpretations evolve, or in preparation for SOC 2 Type II examination cycles.*
