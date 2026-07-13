from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from artifact_trust.errors import PolicyEvaluationError
from artifact_trust.models import PolicyInput
from artifact_trust.policy import evaluate_opa, evaluate_policy


def _input() -> PolicyInput:
    return PolicyInput(
        source_pinned=True,
        signature_valid=True,
        provenance_valid=True,
        artifact_digest_valid=True,
        evidence_digests_valid=True,
        secrets=0,
        critical_vulnerabilities=0,
        high_vulnerabilities=0,
        medium_vulnerabilities=0,
        disallowed_licenses=0,
        unknown_licenses=0,
        unpinned_dependencies=0,
    )


def test_opa_adapter_parses_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "result": [
            {
                "expressions": [
                    {
                        "value": {
                            "decision": "ALLOW",
                            "reasons": ["all mandatory controls passed"],
                            "policy_version": "2026-07-13.1",
                        }
                    }
                ]
            }
        ]
    }
    monkeypatch.setattr("artifact_trust.policy.shutil.which", lambda _: "/usr/bin/opa")
    monkeypatch.setattr(
        "artifact_trust.policy.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(payload)),
    )
    result = evaluate_opa(_input())
    assert result.engine == "opa"
    assert result.decision.value == "ALLOW"


def test_opa_adapter_rejects_invalid_document(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("artifact_trust.policy.shutil.which", lambda _: "/usr/bin/opa")
    monkeypatch.setattr(
        "artifact_trust.policy.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(stdout="{}"),
    )
    with pytest.raises(PolicyEvaluationError, match="invalid decision"):
        evaluate_opa(_input())


def test_opa_adapter_fails_closed_on_process_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("artifact_trust.policy.shutil.which", lambda _: "/usr/bin/opa")

    def fail(*args: object, **kwargs: object) -> None:
        raise subprocess.CalledProcessError(1, ["opa"])

    monkeypatch.setattr("artifact_trust.policy.subprocess.run", fail)
    with pytest.raises(PolicyEvaluationError, match="failed"):
        evaluate_opa(_input())


def test_auto_policy_safely_falls_back_on_malformed_opa_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("artifact_trust.policy.shutil.which", lambda _: "/usr/bin/opa")
    monkeypatch.setattr(
        "artifact_trust.policy.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(stdout="not-json"),
    )
    result = evaluate_policy(_input(), "auto")
    assert result.engine == "fallback"
    assert result.decision.value == "ALLOW"


def test_fallback_reasons_use_the_same_sorted_order_as_rego() -> None:
    candidate = _input().model_copy(
        update={
            "source_pinned": False,
            "signature_valid": False,
            "artifact_digest_valid": False,
        }
    )
    reasons = evaluate_policy(candidate, "fallback").reasons
    assert reasons == tuple(sorted(reasons))


def test_explicit_opa_fails_closed_if_valid_document_diverges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "result": [
            {
                "expressions": [
                    {
                        "value": {
                            "decision": "ALLOW",
                            "reasons": ["all mandatory controls passed"],
                            "policy_version": "2026-07-13.1",
                        }
                    }
                ]
            }
        ]
    }
    monkeypatch.setattr("artifact_trust.policy.shutil.which", lambda _: "/usr/bin/opa")
    monkeypatch.setattr(
        "artifact_trust.policy.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(payload)),
    )
    rejected_input = _input().model_copy(update={"source_pinned": False})
    with pytest.raises(PolicyEvaluationError, match="diverged"):
        evaluate_policy(rejected_input, "opa")
    fallback = evaluate_policy(rejected_input, "auto")
    assert fallback.engine == "fallback"
    assert fallback.decision.value == "REJECT"
