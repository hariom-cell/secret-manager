# section-30

**Source:** §30 — Secret Manager Architecture Study

---

## 30. Supply Chain Security

| Practice | Implementation |
|---|---|
| Dependency pinning | Lock all dependencies to specific versions |
| Dependency auditing | `cargo audit`, Dependabot/Renovate |
| SBOM generation | Generate for each release |
| Minimal dependencies | Audit every dependency |
| Reproducible builds | All releases reproducible from source |
| Signed releases | All packages signed with release key |
| CI/CD hardening | Isolated build environment |
| Build attestation | SLSA provenance for releases |

---
