package artifacttrust_test

import data.artifacttrust
import rego.v1

base_input := {
    "source_pinned": true,
    "signature_valid": true,
    "provenance_valid": true,
    "artifact_digest_valid": true,
    "evidence_digests_valid": true,
    "secrets": 0,
    "critical_vulnerabilities": 0,
    "high_vulnerabilities": 0,
    "medium_vulnerabilities": 0,
    "disallowed_licenses": 0,
    "unknown_licenses": 0,
    "unpinned_dependencies": 0,
    "manifest_coverage_gaps": 0,
    "manifest_integrity_errors": 0,
}

test_allow if {
    result := artifacttrust.decision with input as base_input
    result.decision == "ALLOW"
}

test_quarantine if {
    candidate := object.union(base_input, {"high_vulnerabilities": 1})
    result := artifacttrust.decision with input as candidate
    result.decision == "QUARANTINE"
}

test_reject if {
    candidate := object.union(base_input, {"artifact_digest_valid": false})
    result := artifacttrust.decision with input as candidate
    result.decision == "REJECT"
}

test_complete_evidence_and_manifest_integrity_are_mandatory if {
    candidate := object.union(base_input, {
        "provenance_valid": false,
        "evidence_digests_valid": false,
        "manifest_integrity_errors": 1,
    })
    result := artifacttrust.decision with input as candidate
    result.decision == "REJECT"
    count(result.reasons) == 3
}

test_reject_reasons_are_sorted if {
    candidate := object.union(base_input, {
        "source_pinned": false,
        "signature_valid": false,
        "manifest_integrity_errors": 1,
    })
    result := artifacttrust.decision with input as candidate
    result.reasons == sort(result.reasons)
}
