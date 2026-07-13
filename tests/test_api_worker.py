from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from artifact_trust.api import create_app
from artifact_trust.config import Settings
from artifact_trust.worker import process_next_job


@pytest.mark.integration
def test_api_only_enqueues_then_separate_worker_completes(
    settings: Settings, tmp_path: Path
) -> None:
    client = TestClient(create_app(settings))
    assert client.get("/healthz").json()["status"] == "ok"
    response = client.post(
        "/api/v1/jobs",
        json={
            "source": {"kind": "fixture", "location": "safe-app"},
            "policy_engine": "fallback",
        },
    )
    assert response.status_code == 202
    job = response.json()
    assert job["state"] == "pending"
    assert list((settings.work_root / "results").iterdir()) == []
    assert client.get(f"/api/v1/jobs/{job['id']}/report").status_code == 409

    assert process_next_job(settings) is True
    completed = client.get(f"/api/v1/jobs/{job['id']}").json()
    assert completed["state"] == "completed"
    report = client.get(f"/api/v1/jobs/{job['id']}/report")
    assert report.status_code == 200
    assert report.json()["policy"]["decision"] == "ALLOW"
    html = client.get(f"/api/v1/jobs/{job['id']}/report.html")
    assert html.status_code == 200
    assert "Artifact Trust Report" in html.text


def test_api_rejects_local_and_unknown_fixture(settings: Settings) -> None:
    client = TestClient(create_app(settings))
    local = client.post(
        "/api/v1/jobs",
        json={"source": {"kind": "local", "location": "/tmp"}},
    )
    assert local.status_code == 422
    unknown = client.post(
        "/api/v1/jobs",
        json={"source": {"kind": "fixture", "location": "missing"}},
    )
    assert unknown.status_code == 400


def test_dashboard_has_security_headers(settings: Settings) -> None:
    client = TestClient(create_app(settings))
    response = client.get("/")
    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert client.get("/static/dashboard.js").status_code == 200


def test_api_listing_fixture_catalog_and_missing_job(settings: Settings) -> None:
    client = TestClient(create_app(settings))
    fixtures = client.get("/api/v1/fixtures")
    assert fixtures.status_code == 200
    assert "safe-app" in fixtures.json()["fixtures"]
    assert client.get("/api/v1/jobs").json() == []
    assert client.get("/api/v1/jobs/not-found").status_code == 404


def test_api_rejects_git_when_network_is_disabled(settings: Settings) -> None:
    response = TestClient(create_app(settings)).post(
        "/api/v1/jobs",
        json={
            "source": {
                "kind": "git",
                "location": "https://github.com/o/r.git",
                "commit": "a" * 40,
            }
        },
    )
    assert response.status_code == 400
    assert "disabled" in response.json()["detail"]
