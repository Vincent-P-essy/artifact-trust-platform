# Methodology and evidence contracts

## Experimental questions

The vertical slice answers seven falsifiable questions:

1. Can the same pinned input produce byte-identical evidence?
2. Can a direct dependency and its transitive child be represented in both a graph and SBOM?
3. Can policy distinguish a clean input, review-required risk and mandatory rejection?
4. Does modifying one byte after signing reliably block publication?
5. Does changing any report, SBOM, finding, graph, policy input or decision also fail verification?
6. Can incomplete lock metadata ever reach `ALLOW`?
7. Do source races, symlinks, special files and partial snapshots fail closed and clean up?

The tests use four inert fixtures: safe, known-high-vulnerability, multiple-rejection-condition,
and unpinned-dependency. The safe pipeline runs twice and every generated file is compared byte
for byte. A checked-in golden summary anchors component count, edge count, manifest list, finding
count, transitive node and decision.

Negative tests additionally exercise malformed DSSE structures, duplicate/unsafe subjects,
wrong keys, symlinked evidence, validly re-signed but inconsistent control documents, malformed
OPA output, incomplete package locks, snapshot file/directory/byte limits, FIFOs, symlinks and Git
cleanup. API tests alter a completed signed report and require both JSON and HTML endpoints to
fail closed.

## Source snapshot evidence

Local and fixture inputs are untrusted mutable trees. A single snapshot is therefore created
before the tree digest, archive, parsers or scanners run. Files are opened relative to directory
descriptors with no-follow and nonblocking flags, checked as regular files with `fstat`, copied
under count/size limits, then checked again for device, inode, size, mtime and ctime stability.
The analysis copy is made read-only. This removes the former multi-pass time-of-check/time-of-use
gap: later stages consume the same bytes, not repeated reads of the caller's tree.

Git acquisition fetches only an explicit commit, verifies the resolved object, creates a Git
archive and extracts regular files through a custom bounded extractor. Both successful and failed
materializations are cleaned from the private source area after use.

## Dependency evidence

The npm parser consumes the `packages` map from package-lock v2/v3 and resolves Node's nested
installation paths before falling back to a top-level package. Root manifest dependencies become
direct edges; package entries contribute transitive edges. A package lock whose root is not an
object, whose version is not 2/3, whose packages map is absent, whose root package entry is
missing, or whose dependency edge cannot be resolved produces a manifest-integrity finding and a
deterministic `REJECT`.

Python requirements are components only when constrained by one exact `==` version. PEP 621
dependencies use the same rule. A range, VCS reference, URL, option or invalid line is recorded as
unpinned or incomplete and rejected by policy.

Each component has a stable bom-ref, name, version, ecosystem, package URL, scope, direct flag,
license set and source manifest. The graph JSON is the inspection-friendly contract. CycloneDX is
the exchange contract.

## Offline scanners

Secret patterns are intentionally high-confidence. Reports contain only path, line, kind and a
domain-separated truncated SHA-256 fingerprint; matched bytes are never emitted. Binary samples
are skipped.

Licenses come from lock metadata. A small SPDX allowlist is automatic; strong-copyleft and source-
available families are disallowed by the example policy; absent or nonclassified expressions are
quarantined for review.

The vulnerability database is a versioned JSON snapshot shipped with the package. It contains one
real advisory needed by the vulnerable fixture and one explicitly synthetic advisory needed by
the rejection fixture. Version matching uses PEP 440 semantics through `packaging`. This is a
reproducibility dataset, not a complete advisory service.

## Security score

The report exposes a transparent 0–100 score in addition to the policy decision. It starts at 100
and lists every deduction: 40 for a secret, 30 for a critical vulnerability, 15 for high, 5 for
medium, 20 for a disallowed license, 5 for an unknown license, 20 for an unpinned dependency and
10 for missing manifest coverage. An unpinned source costs 30; invalid signature, provenance,
artifact digest or evidence-set integrity forces the score to zero. Scores are bounded at zero.
This is a triage aid, not a substitute for the fail-closed policy gate.

## Provenance and decision contract

The statement uses in-toto Statement v1 and a SLSA v1 predicate shape. Its closed subject set is
exactly:

- `artifact.tar.gz`;
- `decision.json`;
- `dependency-graph.json`;
- `findings.json`;
- `policy-input.json`;
- `report.html`;
- `report.json`;
- `sbom.cdx.json`.

External parameters identify the canonical source and pinned commit; internal parameters bind the
source tree digest; resolved dependencies contain package URLs without inventing unavailable
package-content digests. The statement separately records whether source acquisition used the
network, that repository code was not executed, and that the bundle build had no network.

The canonical statement is wrapped in DSSE and signed with Ed25519. Publication verification
checks the signature, in-toto/SLSA predicate shape, unique lowercase SHA-256 subjects, exact
subject names, regular non-symlink files and every digest. The API additionally schema-validates
the signed report, decision and policy input, then checks report ID, policy, risk and policy-input
agreement before returning content. It uses the configured trust key, never the key copied into
the result directory.

Policy consumes signature, provenance, artifact-digest and complete-evidence booleans separately.
The controlled tamper scenario demonstrates why an intact DSSE signature alone is insufficient:
the signature can remain valid while a post-signing file digest fails.

## Metrics

`artifact-trust benchmark` measures complete end-to-end local runs after optional warmups using a
monotonic nanosecond clock. It publishes iteration count, p50, nearest-rank p95, mean, min, max,
component count, finding count and decision. Host, filesystem cache and runtime affect timings;
the numbers are performance observations, not signed evidence.

The 2026-07-13 baseline ran 20 measured iterations after two warmups on Python 3.12.13, Linux
5.15.0 and an 11th Gen Intel Core i3-1115G4. The hardened pipeline observed p50 3.530 ms and p95
4.635 ms. The prior source-state observation was p50 2.501 ms and p95 3.293 ms; the new run adds
1.029 ms at p50 in this single-host comparison. That delta includes the immutable snapshot and
multi-file evidence work together and is not an isolated causal benchmark or portable capacity
claim.

The baseline binds this observation to a SHA-256 over the sorted path-and-content hashes of every
tracked or non-ignored repository file, excluding only `benchmarks/baseline.json` to avoid a
self-reference. That content identity remains verifiable after the candidate is committed and is
more precise than publishing a bare `dirty=true` flag. A release benchmark should additionally
record the final clean commit identifier.

## Reproduction gates

CI installs only from `uv.lock`, checks formatting and lint, runs strict mypy, and enforces branch
coverage at 85%. It validates and tests Rego with a digest-pinned OPA image, executes the tamper
gate, builds both wheel and source distribution, installs the wheel into an isolated environment,
and runs the packaged fixture from that installation. Container gates verify the runtime UID and
Git client, exercise an offline packaged fixture, fetch one public repository at an exact commit,
and execute the separated Compose API/worker path. The Compose check proves distinct identities,
completed processing and lack of private-key visibility from the API.
