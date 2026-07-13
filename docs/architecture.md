# Architecture

## Trust boundaries

```text
browser / API client
        |
        v
FastAPI control plane ---- atomic JSON queue ---- worker supervisor
        |                                           |
        | no analysis                               | fixed Python child command
        v                                           v
dashboard                                   resource-limited child
                                                    |
                       validated source -> evidence pipeline -> result directory
```

The API and worker are separate operating-system processes and separate Compose services. The
API accepts named fixtures or commit-pinned Git requests, validates their shape, and performs
one atomic rename into the queue. It has no call path to `run_pipeline`.

The worker supervisor atomically claims one job. It launches a fixed Python module in a child
with CPU, address-space, file-size, descriptor, process-count and wall-clock limits. The child
is the only component that materializes or analyzes source input. The worker writes a completed
record only after `report.json` exists.

## Source boundary

Three source types exist:

1. `fixture`: a conservative name is resolved below the configured fixture root.
2. `local`: CLI-only and explicitly added to that invocation's allowed roots.
3. `git`: HTTPS, exact allowlisted host, port 443, no credentials/query/fragment, and a full
   40-character commit identifier.

Git is invoked with an argument vector, never a shell. Prompts, hooks, HTTP redirects, file
protocol and LFS smudging are disabled. The fetched commit must equal the requested identifier. `git archive`
materializes the tree, after which custom extraction rejects absolute paths, traversal, links,
devices and oversized archives.

## Evidence pipeline

```text
safe regular files
   +-- canonical tree digest
   +-- deterministic tar.gz artifact
   +-- manifest parsers -- dependency graph -- CycloneDX 1.6
   +-- offline scanners -- normalized redacted findings

artifact digest + source digest + graph
   -> in-toto Statement v1 / SLSA-shaped predicate
   -> DSSE Ed25519 signature
   -> signature and subject verification

verification + findings + pinning
   -> policy input
   -> OPA or deterministic fallback
   -> ALLOW / QUARANTINE / REJECT
   -> JSON and escaped HTML reports
```

Source tree hashing includes portable relative paths, sizes and bytes in sorted order. VCS
metadata, dependency caches, virtual environments and bytecode caches are outside the evidence
boundary. Symbolic links are rejected rather than followed.

## Determinism

The bundle uses sorted entries, uid/gid zero, fixed permissions and gzip/tar timestamps at zero.
JSON is sorted and serialized without locale-dependent formatting. Report identifiers are
content-derived. Ed25519 signatures are deterministic for a fixed key and statement. The same
source, policy version, advisory snapshot, tool version and key therefore produce byte-identical
evidence. Runtime benchmark timings are kept in a separate metrics document.

## Key model

`ATP_PRIVATE_KEY` and `ATP_PUBLIC_KEY` select an operator-managed Ed25519 pair. The pipeline
verifies that the pair matches before signing. If no key is configured, a development pair is
created once below the mode-0700 work root. This makes local evaluation runnable but is not a
production trust bootstrap. Production consumers must pin the public key out of band and protect
the private key with a secret mount or signing service.

## Deployment profiles

The default Compose topology disables worker networking. Both services are unprivileged,
read-only, capability-free and constrained. Remote Git support is an explicit deployment change:
the API and worker must receive `ATP_ALLOW_NETWORK=1`, the host allowlist must be narrow, and the
worker must receive egress only to the approved Git service through a proxy or firewall.
