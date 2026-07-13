# Known limitations

This is a complete vertical slice, not a general-purpose build service.

- It creates a deterministic source artifact; it does not compile or run untrusted projects.
  Build-step provenance, hermetic compiler images and binary reproducibility remain future work.
- Built-in manifest support is limited to npm package-lock v2/v3, PEP 621 dependencies and simple
  requirements files. Poetry, uv, pnpm, Yarn, Maven, Gradle, Go and Cargo need dedicated parsers.
- Python requirements do not expose a transitive graph without a lock format that records one.
- npm workspace, peer-dependency and exotic link semantics are only represented when resolved
  package-lock paths make the edge explicit. Ambiguity now fails closed; it is not reconstructed.
- The built-in advisory snapshot is intentionally small and ages until the file is updated. Syft,
  Grype and Gitleaks adapters require separately pinned binaries/databases and are not merged into
  the signed default decision.
- License expression handling is conservative token classification, not full SPDX expression or
  legal compatibility analysis.
- Secret detection is pattern-based. It can miss encoded/custom secrets and can flag documented
  examples. Entropy, verification and repository-history scanning are future work.
- Git commit identifiers use the 40-character SHA-1 form accepted by broadly deployed Git hosting.
  Git SHA-256 repositories are not yet supported.
- Descriptor-based snapshots rely on Linux/POSIX filesystem behavior. `O_NOFOLLOW` is used when the
  platform exposes it; production deployment should remain on a tested Linux filesystem.
- Process resource limits and container restrictions are defense in depth, not a VM boundary.
- The filesystem queue is suitable for one host and modest concurrency. It has no distributed
  lease, retry backoff, dead-letter retention policy or multi-host transaction guarantee.
- The API has no authentication, tenant isolation, TLS termination, rate limit or authorization
  model. Bind it to loopback for local use or place it behind an authenticated gateway.
- The Compose worker owns the result volume and signing key. A compromised worker can therefore
  replace and re-sign internally consistent evidence; append-only storage and remote/KMS signing
  are production requirements.
- The one-shot Compose volume initializer runs as UID 0 with only `CHOWN` and `FOWNER` capabilities
  to establish numeric ownership on fresh volumes. It is networkless and read-only outside those
  mounts, but production orchestrators should provision persistent-volume permissions separately.
- Development key auto-generation is convenient but does not establish trust. The emitted
  `verification-key.pem` is not self-authenticating. Production requires managed signing, key
  rotation/revocation and public keys pinned through a separate channel.
- The HTML dashboard is an operational view, not a full dependency visualization UI.
- Rego equivalence is tested for the policy cases in this repository, checked at runtime for each
  evaluation, and CI runs a digest-pinned OPA image. The fallback remains a second implementation
  that must be maintained whenever policy fields change.
- The container installs Git from the digest-pinned Debian base image's configured package
  repositories at build time; the final image digest should be recorded by a release pipeline.
- The remote-Git container gate depends on the availability of one public, exact-commit GitHub
  repository. All core unit/integration tests remain offline.
- Performance metrics describe the measured machine and cache state; they are not portable claims.
