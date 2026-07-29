# ADR-006: cosign for Container Image Signing and Provenance Attestation

## Status

Accepted

## Date

2025-01-15

## Context

The Secure Software Factory must provide cryptographic assurance that deployed container images:
1. Were built by the authorized CI/CD pipeline (not tampered with post-build)
2. Originate from a known source repository and commit
3. Have verifiable provenance (who built it, when, from what source)

This is required for SOC 2 CC7.2 (change management integrity), CNBV/IFPE operational security controls, and general supply-chain security (preventing image substitution attacks). The signing mechanism must work within GitHub Actions without manual key management.

Key constraints:
- Must sign container images with cryptographic proof of pipeline origin
- Must attach provenance attestations (SLSA-compatible)
- Must work with GitHub Actions OIDC (keyless signing preferred to avoid key management)
- Must support verification by downstream consumers (deployment pipelines, registries)
- Must integrate with Syft SBOM attachment
- Must not require manual key rotation or HSM infrastructure at current scale

## Decision

Use **cosign** (by Sigstore) for keyless container image signing using GitHub Actions OIDC identity, with SLSA provenance attestation attached to signed images.

## Alternatives Considered

### Alternative 1: Docker Content Trust (DCT) / Notary v1

- **Pros:** Native Docker integration, established tool, server-based trust delegation
- **Cons:** Requires Notary server infrastructure, complex key management (root keys, delegation keys), no OIDC/keyless support, limited attestation capabilities, being superseded by Notary v2

### Alternative 2: Notary v2 (ORAS Signatures)

- **Pros:** OCI-native signatures, registry-stored (no separate infrastructure), backed by CNCF
- **Cons:** Still maturing (less production adoption than cosign), limited GitHub Actions integration, no keyless signing via OIDC yet, smaller community and tooling ecosystem

### Alternative 3: AWS Signer (Commercial)

- **Pros:** Managed service, integrates with ECR and AWS deployment tools, KMS-backed keys
- **Cons:** AWS-specific (vendor lock-in), per-signature pricing, limited to AWS ecosystem, no SLSA provenance support, does not work with non-AWS registries

### Alternative 4: GPG signing (manual)

- **Pros:** Well-understood technology, no vendor dependency, proven cryptography
- **Cons:** Manual key management burden, no keyless option, key distribution problem, no native container image support (requires wrapping), no OIDC integration, rotation complexity

### Alternative 5: HashiCorp Vault Transit (for signing)

- **Pros:** Centralized key management, audit logging, good for enterprise key governance
- **Cons:** Requires Vault infrastructure ($$$), added complexity, not designed for container signing specifically, no SLSA provenance, additional latency for signing operations

## Consequences / Trade-offs

### Positive

- **Keyless signing**: Uses GitHub Actions OIDC tokens — no long-lived keys to manage, rotate, or protect
- Zero licensing cost (Sigstore public infrastructure)
- Native SLSA provenance attestation support
- Broad ecosystem adoption (Kubernetes, OCI registries, policy engines)
- Signatures stored in the OCI registry alongside the image (no separate infrastructure)
- Supports SBOM attachment as in-toto attestation (integrates with Syft)
- Verification can be enforced at deployment time (admission controllers, Kyverno, etc.)
- Transparency log (Rekor) provides tamper-evident record of all signing events
- Active CNCF project with strong community and corporate backing

### Negative

- Keyless signing depends on Sigstore public infrastructure (Fulcio CA, Rekor log) — availability risk
- Short-lived certificates (10 min) mean verification requires checking the Rekor transparency log (not just the certificate)
- Learning curve for teams unfamiliar with Sigstore/OIDC concepts
- Verification policy configuration (e.g., which OIDC issuers to trust) requires careful setup
- Public Rekor log means signing events are publicly visible (though image content is not exposed)
- If Sigstore infrastructure has an outage, signing (and verification) may fail

## False-Positive Management Strategy

Container signing has a binary outcome (valid/invalid signature) rather than a traditional false-positive profile. The management strategy focuses on **verification policy**:

1. **OIDC issuer pinning**: Verification policies only trust signatures from GitHub Actions OIDC issuer (`https://token.actions.githubusercontent.com`) for the specific repository, preventing acceptance of signatures from unauthorized sources.
2. **Certificate identity matching**: Verify that the signing certificate's subject matches the expected workflow path (e.g., `.github/workflows/security-pipeline.yml`).
3. **Rekor entry verification**: Always verify signatures against the Rekor transparency log to catch certificate expiration edge cases.
4. **Grace period for transitions**: When rotating signing identities (e.g., repo rename, workflow restructure), maintain verification of both old and new identities for a transition period.
5. **Offline verification fallback**: Cache Rekor inclusion proofs for critical images to support verification during Sigstore outages.

## OSS vs Commercial Justification

cosign was chosen over commercial alternatives for the following reasons:

| Factor | cosign/Sigstore (OSS) | Docker Content Trust | AWS Signer | Vault Transit |
|--------|----------------------|---------------------|-----------|---------------|
| Annual cost | $0 | $0 (+ infra cost) | Per-signature pricing | $10K+ (Vault license) |
| Keyless signing | Yes (OIDC) | No | No (KMS keys) | No |
| Key management | None required | Complex | AWS KMS | Vault infrastructure |
| SLSA provenance | Native | No | No | No |
| SBOM attestation | Native | No | No | No |
| GitHub Actions | Excellent | Limited | AWS-only | Requires setup |
| Registry support | Any OCI registry | Docker Hub-focused | ECR only | N/A |
| Verification tools | cosign verify, Kyverno | Docker CLI | AWS APIs | Custom |
| Transparency log | Rekor (public) | No | CloudTrail | Vault audit |

For the organization's requirements:
1. **Keyless signing eliminates key management operational burden** — critical for a 25-person team without dedicated PKI staff.
2. **SLSA provenance is a differentiator** — provides auditors with cryptographic proof of build origin, strengthening SOC 2 and CNBV compliance posture.
3. **SBOM attestation via cosign** — creates a complete evidence chain (image → signature → SBOM → provenance) in a single workflow.
4. **No vendor lock-in** — cosign works with any OCI registry, not tied to a cloud provider.
5. **Industry momentum** — Kubernetes ecosystem is converging on Sigstore for supply-chain security (Kubernetes itself uses cosign for release signing).

## References

- [cosign GitHub Repository](https://github.com/sigstore/cosign)
- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Keyless Signing with GitHub Actions](https://docs.sigstore.dev/signing/signing_with_containers/#keyless-signing-with-github-actions)
- [SLSA Framework](https://slsa.dev/)
- [Rekor Transparency Log](https://docs.sigstore.dev/logging/overview/)
- [In-toto Attestation Framework](https://github.com/in-toto/attestation)
