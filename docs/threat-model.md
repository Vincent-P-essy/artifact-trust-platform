# Threat model

## Assets

- signing-key confidentiality and integrity;
- trusted public-key distribution;
- source and artifact digest integrity;
- policy and advisory snapshot integrity;
- queue state and completed reports;
- API/worker availability;
- absence of secrets in reports and logs.

## Adversaries

The design considers a malicious repository author, a caller attempting SSRF or path traversal, a
dependency author controlling manifest fields, a user attempting queue/result path manipulation,
and an attacker modifying artifacts after analysis. Host administrators and a compromised CI runner
remain outside the isolation guarantee.

## Controls

| Threat | Control | Residual risk |
|---|---|---|
| repository command execution | no builds or package-manager hooks; fixed Git-only acquisition | parser/library flaws still exist |
| SSRF and credential leakage | HTTPS only, exact host allowlist, port 443, no userinfo/query/fragment, network off by default | DNS and approved-host compromise require egress controls |
| mutable revision | full commit identifier required and verified after fetch | SHA-1 collision resistance is inherited from Git's object model |
| archive traversal or device creation | manual extraction rejects absolute/traversal paths, links and special files | resource exhaustion bounded but not eliminated |
| symlink escape | all analysis rejects symbolic links | legitimate linked content needs preprocessing |
| decompression/resource bomb | file count, per-file and total-size limits; child CPU/memory/file/PID/wall limits | kernel and container runtime remain trusted |
| API remote-code execution | API only validates and atomically queues; worker child is a process boundary | shared host compromise can cross process boundaries |
| secret disclosure in evidence | only redacted type/path/line/fingerprint is emitted | source remains visible to the worker |
| post-signing artifact replacement | subject digest compared after signature verification; policy rejects mismatch | trusted public key must be pinned externally |
| policy bypass when OPA is absent | tested deterministic fallback; explicit OPA mode fails closed | policy equivalence must be regression-tested when changed |
| queue path injection | generated alphanumeric IDs, fixed directories, result containment checks | filesystem owner can modify records |
| HTML injection | server-side escaping; dashboard uses `textContent`; restrictive CSP | OpenAPI remains served by framework defaults |

## Security invariants

1. The API process never calls the evidence pipeline.
2. A Git request without network opt-in, approved host and exact commit cannot be queued.
3. A source link or special file cannot enter the artifact.
4. Raw secret matches cannot enter finding evidence.
5. Invalid signature or artifact binding always produces `REJECT`.
6. External scanners are never invoked by default or selected from user-provided executable names.
7. A completed job record always references a report below the configured work root.

## Operational hardening

Production deployment should place source acquisition in a dedicated node or microVM, use an
egress proxy, mount the signing key read-only from a secret manager, publish verification keys
through a separate trust channel, make results append-only, authenticate the API, terminate TLS at
a hardened proxy, set request/body/rate limits, and forward audit events to an immutable store.
