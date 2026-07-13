# Threat model

## Assets

- signing-key confidentiality and integrity;
- trusted public-key distribution;
- source, artifact and evidence-bundle integrity;
- policy and advisory snapshot integrity;
- queue state, decisions and completed reports;
- API/worker availability;
- absence of secrets in reports and logs.

## Adversaries

The design considers a malicious repository author, a caller attempting SSRF or path traversal, a
dependency author controlling manifest fields, a user attempting queue/result path manipulation,
an attacker racing a mutable local tree, and an attacker modifying any evidence file after
analysis. Host administrators, a compromised worker or signing service, and a compromised CI
runner remain outside the isolation guarantee.

## Controls

| Threat | Control | Residual risk |
|---|---|---|
| repository command execution | no builds or package-manager hooks; fixed Git-only acquisition | parser/library flaws still exist |
| SSRF and credential leakage | HTTPS only, exact host allowlist, port 443, no userinfo/query/fragment, network off by default | DNS and approved-host compromise require egress controls |
| mutable revision | full commit identifier required and verified after fetch | SHA-1 collision resistance is inherited from Git's object model |
| mutable local/fixture input | one descriptor-based, no-follow snapshot; metadata stability checks; read-only analysis copy | the Linux kernel and source filesystem semantics remain trusted |
| archive traversal or device creation | manual extraction rejects absolute/traversal paths, links and special files | resource exhaustion is bounded but not eliminated |
| symlink or special-file escape | snapshot and Git extraction reject links, devices, FIFOs and sockets | legitimate linked content needs preprocessing |
| decompression/resource bomb | file count, per-file and total-size limits; child CPU/memory/file/PID/wall limits | kernel and container runtime remain trusted |
| API remote-code execution through a repository | API only validates and atomically queues; worker child is a process boundary | shared host compromise can cross process boundaries |
| signing-key disclosure to API | private-key volume is worker-only; API receives only the public-key volume | a compromised worker still has signing authority |
| secret disclosure in evidence | only redacted type/path/line/fingerprint is emitted | source remains visible to the worker |
| post-signing evidence replacement | exact eight-subject set and every SHA-256 digest are verified before CLI/API consumption | trusted public key must be pinned externally |
| partial-envelope downgrade | CLI requires the complete subject set; API always uses closed-set verification | programmatic artifact-only helper is for the controlled tamper lab, not publication verification |
| inconsistent decision documents | signed report, decision and policy-input documents are schema-validated and cross-checked | a trusted signer can still authorize a malicious but internally consistent result |
| incomplete dependency lock | parser warnings become high-severity manifest-integrity findings and force `REJECT` | unsupported ecosystem semantics remain conservative limitations |
| policy bypass or engine drift | runtime equality check for decision/reasons/version; explicit OPA mode fails closed; pinned OPA check/test runs in CI | `auto` intentionally uses the deterministic fallback when OPA is unavailable or divergent |
| queue path injection | generated alphanumeric IDs, fixed directories, strict path resolution and containment | filesystem owner can modify records |
| API modification of completed output | worker-owned state directories; nested result volume is read-only in the API | worker and host retain write access |
| HTML injection | server-side escaping, dashboard `textContent`, restrictive CSP and verified HTML digest | OpenAPI remains served by framework defaults |

## Security invariants

1. The API process never calls the evidence pipeline and never receives the private-key volume.
2. A Git request without network opt-in, approved host and exact commit cannot be queued.
3. Every downstream stage reads one immutable snapshot; a link or special file cannot enter it.
4. Raw secret matches cannot enter finding evidence.
5. Invalid signature, provenance shape, subject set, artifact digest or evidence digest blocks
   verification and forces policy rejection when represented as policy input.
6. A publication envelope binds exactly eight named evidence subjects; artifact-only verification
   is not an accepted CLI publication contract.
7. Manifest parse/integrity warnings cannot produce `ALLOW`.
8. OPA and fallback decisions, reasons and versions must match; reasons are deterministic and sorted.
9. External scanners are never invoked by default or selected from user-provided executable names.
10. A completed job record resolves to `report.json` below the configured work root and is served
    only after signed-evidence and control-document verification.

## Operational hardening

Production deployment should place source acquisition in a dedicated node or microVM, use an
egress proxy, replace local key bootstrap with a KMS/HSM-backed signing service, distribute and
rotate verification keys through a separate trust channel, make results append-only, authenticate
and authorize the API, terminate TLS at a hardened proxy, set request/body/rate limits, and forward
audit events to an immutable store. The repository's Compose profile demonstrates least-privilege
mounts and identities; it is not a multi-tenant production security boundary.
