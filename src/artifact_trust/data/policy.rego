package artifacttrust

import rego.v1

policy_version := "2026-07-12.1"

reject_reasons contains "source is not pinned" if not input.source_pinned
reject_reasons contains "provenance signature is invalid" if not input.signature_valid
reject_reasons contains "artifact digest does not match provenance" if not input.artifact_digest_valid
reject_reasons contains "potential secrets detected" if input.secrets > 0
reject_reasons contains "critical vulnerabilities detected" if input.critical_vulnerabilities > 0
reject_reasons contains "disallowed licenses detected" if input.disallowed_licenses > 0
reject_reasons contains "dependencies are not exactly pinned" if input.unpinned_dependencies > 0

quarantine_reasons contains "high vulnerabilities require review" if input.high_vulnerabilities > 0
quarantine_reasons contains "medium vulnerabilities require review" if input.medium_vulnerabilities > 0
quarantine_reasons contains "unknown licenses require review" if input.unknown_licenses > 0
quarantine_reasons contains "dependency manifest coverage requires review" if input.manifest_coverage_gaps > 0

decision := {
    "decision": "REJECT",
    "reasons": sort([reason | reject_reasons[reason]]),
    "policy_version": policy_version,
} if count(reject_reasons) > 0

decision := {
    "decision": "QUARANTINE",
    "reasons": sort([reason | quarantine_reasons[reason]]),
    "policy_version": policy_version,
} if {
    count(reject_reasons) == 0
    count(quarantine_reasons) > 0
}

decision := {
    "decision": "ALLOW",
    "reasons": ["all mandatory controls passed"],
    "policy_version": policy_version,
} if {
    count(reject_reasons) == 0
    count(quarantine_reasons) == 0
}
