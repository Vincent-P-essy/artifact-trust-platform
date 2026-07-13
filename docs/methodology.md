# Methodology and evidence contracts

## Experimental questions

The first vertical slice answers four falsifiable questions:

1. Can the same pinned input produce byte-identical evidence?
2. Can a direct dependency and its transitive child be represented in both a graph and SBOM?
3. Can policy distinguish a clean input, review-required risk and mandatory rejection?
4. Does modifying one byte after signing reliably block publication?

The tests use four inert fixtures: safe, known-high-vulnerability, multiple-rejection-condition,
and unpinned-dependency. The safe pipeline runs twice and every generated file is compared byte
for byte. A checked-in golden summary anchors component count, edge count, manifest list, finding
count, transitive node and decision.

## Dependency evidence

The npm parser consumes the `packages` map from package-lock v2/v3 and resolves Node's nested
installation paths before falling back to a top-level package. Root manifest dependencies become
direct edges; package entries contribute transitive edges. Python requirements are components only
when constrained by one exact `==` version. PEP 621 dependencies use the same rule. A range, VCS
reference, URL, option or invalid line is recorded as unpinned and rejected by policy.

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
10 for missing manifest coverage. An unpinned source costs 30; invalid integrity evidence forces
the score to zero. Scores are bounded at zero. This is a triage aid, not a substitute for the
fail-closed policy gate.

## Provenance

The statement uses in-toto Statement v1 and a SLSA v1 predicate shape. Its subject is exactly one
artifact named `artifact.tar.gz`. External parameters identify the canonical source and pinned
commit; internal parameters bind the source tree digest; resolved dependencies contain package
URLs without inventing unavailable package-content digests. The statement separately records
whether source acquisition used the network, that repository code was not executed, and that the
bundle build had no network.

The canonical statement is wrapped in DSSE and signed with Ed25519. Verification performs both
cryptographic signature validation and artifact SHA-256 comparison. Policy consumes these two
booleans separately so the controlled tamper scenario demonstrates that an intact signature alone
is insufficient.

## Metrics

`artifact-trust benchmark` measures full end-to-end local runs after optional warmups using a
monotonic nanosecond clock. It publishes iteration count, p50, nearest-rank p95, mean, min, max,
component count, finding count and decision. Host, filesystem cache and runtime affect timings;
the numbers are performance observations, not signed evidence.
The checked-in baseline keeps the exact command, runtime, kernel, CPU and source-state context so
future runs can be compared without presenting a single workstation result as a universal claim.

## Reproduction gates

CI installs only from `uv.lock`, checks formatting and lint, runs strict mypy, runs branch coverage,
executes the tamper gate, builds a wheel and builds the container. Test success is not inferred from
the absence of tests: the workflow fails below the configured coverage threshold.
