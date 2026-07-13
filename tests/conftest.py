from __future__ import annotations

from pathlib import Path

import pytest

from artifact_trust.config import Settings
from artifact_trust.models import SandboxPolicy

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PROJECT_ROOT / "fixtures"
TEST_KEYS = PROJECT_ROOT / "tests" / "keys"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        work_root=tmp_path / "work",
        fixtures_root=FIXTURES,
        allowed_local_roots=(FIXTURES,),
        allowed_git_hosts=("github.com",),
        network_enabled=False,
        sandbox=SandboxPolicy(),
        private_key_path=TEST_KEYS / "test-signing-key.pem",
        public_key_path=TEST_KEYS / "test-verification-key.pem",
        source_date_epoch=0,
    )
