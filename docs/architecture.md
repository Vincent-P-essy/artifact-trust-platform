# Architecture

## Trust boundaries

```text
browser / API client
        |
        v
FastAPI control plane ---- pending/ queue ---- worker supervisor
        |                         |                 |
        | public key only         | atomic rename   | private key only
        | results read-only       v                 v
        +---------------- completed state    resource-limited child
                                                    |
                         immutable snapshot -> evidence pipeline -> signed result
```

The API and worker are separate operating-system processes and separate Compose services. The
API accepts named fixtures or commit-pinned Git requests, validates their shape, and writes one
record into `pending`. It has no call path to `run_pipeline`. When serving a completed result it
uses the externally configured public key to verify the DSSE signature, exact evidence subject
set, all evidence digests and control-document consistency before returning JSON or HTML.

The worker supervisor atomically claims one job. It launches a fixed Python module in a child
with CPU, address-space, file-size, descriptor, process-count and wall-clock limits. The child
is the only component that materializes or analyzes source input. The worker writes a completed
record only after `report.json` exists. Queue transitions use one filesystem, so `os.replace`
remains atomic; splitting each state into a separate volume would break this property with
cross-device rename errors.

## Source boundary

Three source types exist:

1. `fixture`: a conservative name is resolved below the configured fixture root.
2. `local`: CLI-only and explicitly added to that invocation's allowed roots.
3. `git`: HTTPS, exact allowlisted host, port 443, no credentials/query/fragment, and a full
   40-character commit identifier.

Before hashing or parsing, fixture and local inputs are copied once into a private snapshot.
Directory descriptors, `O_NOFOLLOW`, regular-file `fstat` checks, nonblocking opens and
before/after metadata comparisons reject symlinks, special files and files changed during the
copy. Count and size limits are enforced while copying. Snapshot files are read-only for the rest
of the pipeline and are removed on both success and failure, so every downstream stage observes
the same bytes.

Git is invoked with an argument vector, never a shell. Prompts, hooks, HTTP redirects, file
protocol and LFS smudging are disabled. The fetched commit must equal the requested identifier.
`git archive` materializes the tree, after which custom extraction rejects absolute paths,
traversal, links, devices and oversized archives. Failed fetches and partial materializations are
removed. The extracted source is sealed read-only before analysis.

## Evidence pipeline

```text
one read-only source snapshot
   +-- canonical tree digest
   +-- deterministic tar.gz artifact
   +-- manifest parsers -- dependency graph -- CycloneDX 1.6
   +-- offline scanners -- normalized redacted findings

provisional integrity state + findings + pinning
   -> policy input
   -> OPA or deterministic fallback
   -> ALLOW / QUARANTINE / REJECT
   -> decision, JSON and escaped HTML reports

artifact + decision + graph + findings + policy input + SBOM + both reports
   -> SHA-256 closed subject set
   -> in-toto Statement v1 / SLSA-shaped predicate
   -> DSSE Ed25519 signature
   -> signature, provenance shape, exact subjects and every digest verified
   -> atomic publication of the result directory
```

Source tree hashing includes portable relative paths, sizes and bytes in sorted order. VCS
metadata, dependency caches, virtual environments and bytecode caches are outside the evidence
boundary. Symbolic links are rejected rather than followed.

## Determinism

The bundle uses sorted entries, uid/gid zero, fixed permissions and gzip/tar timestamps at zero.
JSON is sorted and serialized without locale-dependent formatting. Report identifiers are
content-derived. Policy reasons and DSSE subjects are sorted. Ed25519 signatures are
deterministic for a fixed key and statement. The same source, policy version, advisory snapshot,
tool version and key therefore produce byte-identical evidence. Runtime benchmark timings are
kept in a separate metrics document.

## Key model

`ATP_PRIVATE_KEY` and `ATP_PUBLIC_KEY` select an operator-managed Ed25519 pair. The pipeline
verifies that the pair matches before signing. A configured pair can be bootstrapped only when
both paths are absent; a public-key-only process can verify but cannot sign. If neither setting is
configured, a development pair is created once below the mode-0700 work root. This makes local
evaluation runnable but is not a production trust bootstrap. The emitted `verification-key.pem`
is a convenience copy, not proof of identity: consumers must pin the public key out of band.

Compose mounts the private-key volume only into the worker. The public-key volume is writable by
the worker for first-use bootstrap and read-only in the API. A production deployment should
replace bootstrap with a pre-provisioned secret or signing service and make public-key
distribution an independently governed channel.

## Deployment profiles

The default Compose topology disables worker networking. API UID 10001 and worker UID 10002 use a
shared group only where data must cross the boundary. A networkless, one-shot `volume-init` service
creates numeric ownership and permissions on fresh volumes; `nocopy` disables concurrent image
copy-up, avoiding first-start races when API and worker containers are created together. The queue
is one volume for atomic state changes; directory ownership permits the API to write `pending` and
read state but not modify worker-owned `running`, `completed`, or `failed`. A nested result volume
is read-only in the API. The source directory is a worker-only tmpfs and the signing-key volume is
absent from the API.

Both services are unprivileged, read-only, capability-free and constrained. Remote Git support is
an explicit deployment change: the API and worker must receive `ATP_ALLOW_NETWORK=1`, the host
allowlist must be narrow, and the worker must receive egress only to the approved Git service
through a proxy or firewall.
