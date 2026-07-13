# Known limitations

This is a complete vertical slice, not a general-purpose build service.

- It creates a deterministic source artifact; it does not compile or run untrusted projects.
- Built-in manifest support is limited to npm package-lock v2/v3, PEP 621 dependencies and simple
  requirements files. Poetry, uv, pnpm, Yarn, Maven, Gradle, Go and Cargo need dedicated parsers.
- Python requirements do not expose a transitive graph without a lock format that records one.
- npm workspace, peer-dependency and exotic link semantics are only represented when resolved
  package-lock paths make the edge explicit.
- The built-in advisory snapshot is intentionally small and ages until the file is updated. Syft,
  Grype and Gitleaks adapters require separately pinned binaries/databases and are not merged into
  the signed default decision.
- License expression handling is conservative token classification, not full SPDX expression or
  legal compatibility analysis.
- Secret detection is pattern-based. It can miss encoded/custom secrets and can flag documented
  examples. Entropy, verification and repository-history scanning are future work.
- Git commit identifiers use the 40-character SHA-1 form accepted by broadly deployed Git hosting.
  Git SHA-256 repositories are not yet supported.
- Process resource limits and container restrictions are defense in depth, not a VM boundary.
- The filesystem queue is suitable for one host and modest concurrency. It has no distributed
  lease, retry backoff, dead-letter retention policy or multi-host transaction guarantee.
- The API has no authentication, tenant isolation, TLS termination, rate limit or authorization
  model. Bind it to loopback for local use or place it behind an authenticated gateway.
- Development key auto-generation below the work root is convenient but does not establish trust.
  Production requires managed signing and externally pinned public keys.
- The HTML dashboard is an operational view, not a full dependency visualization UI.
- Rego parity is supplied as source; CI exercises the fallback because OPA is optional. Deployments
  using OPA should add the chosen pinned OPA binary to their test matrix.
- Performance metrics describe the measured machine and cache state; they are not portable claims.
