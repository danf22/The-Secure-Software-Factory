# ADR-005: Syft for SBOM Generation

## Status

Accepted

## Date

2025-01-15

## Context

Regulatory requirements (CNBV/IFPE operational security and SOC 2 CC7.1) mandate a complete inventory of all software components in deployed artifacts. A Software Bill of Materials (SBOM) provides this inventory, enabling vulnerability tracking, license compliance, and supply-chain transparency. The SBOM must capture both OS-level packages (from the container base image) and application-level dependencies (Python packages) in a standard, machine-readable format.

Key constraints:
- Must generate SBOM for container images (OS packages + application dependencies)
- Must output in a standard format (SPDX or CycloneDX) accepted by auditors
- Must run within the pipeline's time budget
- Must be attachable to the container image as an attestation (for cosign integration)
- Must capture complete dependency trees including transitive dependencies

## Decision

Use **Syft** (by Anchore) for SBOM generation, producing SPDX 2.3 JSON format output that is stored as a build artifact and attached to the signed container image.

## Alternatives Considered

### Alternative 1: Trivy SBOM mode (`trivy image --format spdx-json`)

- **Pros:** Already using Trivy for scanning (single tool), supports SPDX and CycloneDX output, no additional binary needed
- **Cons:** SBOM generation is secondary to Trivy's scanning focus, less comprehensive package detection than Syft for some ecosystems, mixing SBOM generation with vulnerability scanning conflates concerns

### Alternative 2: CycloneDX CLI tools

- **Pros:** CycloneDX is gaining OWASP backing, good ecosystem-specific tools (cdxgen), supports VEX
- **Cons:** Fragmented tooling (different tool per ecosystem), no single binary for container-level SBOM, less integration with cosign attestation workflow, multiple tools to maintain

### Alternative 3: Docker Scout SBOM

- **Pros:** Integrated with Docker Hub, automatic SBOM for pushed images, good UI
- **Cons:** Requires Docker subscription for full features, proprietary format conversion needed, limited to Docker Hub ecosystem, SBOM not independently verifiable

### Alternative 4: Snyk Container SBOM (Commercial)

- **Pros:** Integrated with vulnerability data, license compliance, managed service
- **Cons:** Part of Snyk paid bundle, cloud-dependent, proprietary format, additional vendor dependency

### Alternative 5: Microsoft SBOM Tool (sbom-tool)

- **Pros:** Microsoft-backed, supports SPDX, designed for CI/CD integration
- **Cons:** Primarily optimized for .NET ecosystem, less mature for Python/container analysis, smaller community than Syft

## Consequences / Trade-offs

### Positive

- Zero licensing cost with active Anchore community maintenance
- Comprehensive package detection across 40+ ecosystems (Python, OS, Go, etc.)
- Native SPDX 2.3 and CycloneDX output — auditor-accepted formats
- Fast execution (~10-20s for typical container images)
- Designed for container image analysis — captures both OS and application layers
- Direct integration with cosign for SBOM attestation attachment
- Single binary with no server infrastructure required
- Supports scanning both container images and filesystem directories
- Actively maintained with frequent releases and ecosystem additions

### Negative

- Does not perform vulnerability analysis (only inventories — Trivy handles CVE detection)
- SBOM accuracy depends on package manager metadata quality (missing lock files reduce precision)
- Adds another binary to the CI environment (though minimal footprint)
- SPDX format is verbose — large images produce large SBOM files
- No built-in license compliance analysis (requires additional tooling if needed)

## False-Positive Management Strategy

SBOM generation has a different false-positive profile than vulnerability scanners. The concern is **completeness** rather than false positives:

1. **Package detection validation**: Periodically verify that all known dependencies from `requirements.txt` appear in the SBOM. Missing packages indicate detection gaps.
2. **Layer-aware analysis**: Syft scans all image layers — verify that build-time dependencies (not present in final image) are not incorrectly included in the runtime SBOM.
3. **Multi-stage build handling**: For multi-stage Docker builds, run Syft only on the final stage image to avoid including build-tool dependencies.
4. **Version accuracy checks**: Cross-reference SBOM package versions against lock files to detect version detection errors.
5. **Phantom package filtering**: Some OS package databases report installed-but-removed packages. Configure Syft to detect only packages with files present on the filesystem.

## OSS vs Commercial Justification

Syft was chosen over commercial alternatives for the following reasons:

| Factor | Syft (OSS) | Snyk SBOM | Docker Scout | Commercial SBOM platforms |
|--------|-----------|-----------|-------------|--------------------------|
| Annual cost | $0 | ~$15K (bundle) | Docker sub | $10K–$50K |
| Output format | SPDX, CycloneDX | Proprietary + SPDX | Proprietary | Varies |
| cosign integration | Native | No | No | Varies |
| Container support | Excellent | Good | Good | Varies |
| Offline operation | Yes | No | No | Varies |
| Ecosystem coverage | 40+ | 30+ | Container-focused | Varies |

For the organization's compliance needs:
1. **SBOM is an evidence artifact** — the format and content matter more than the tool's UI. Syft produces standards-compliant SPDX that satisfies auditor requirements.
2. **cosign attestation integration** — Syft's output integrates directly with cosign for attaching the SBOM to the signed image, creating a complete provenance chain.
3. **No vendor dependency for evidence** — compliance evidence should not depend on a commercial vendor's availability or pricing changes.
4. **Reproducibility** — Syft runs deterministically on the same image, producing consistent SBOMs regardless of external service availability.

## References

- [Syft GitHub Repository](https://github.com/anchore/syft)
- [SPDX Specification](https://spdx.github.io/spdx-spec/v2.3/)
- [NTIA Minimum Elements for SBOM](https://www.ntia.gov/sites/default/files/publications/sbom_minimum_elements_report_0.pdf)
- [Syft + cosign Integration](https://github.com/anchore/syft#cosign-support)
- [Executive Order 14028 — SBOM Requirements](https://www.cisa.gov/sbom)
