"""Resource-limited child entrypoint. It is never imported by the API."""

from __future__ import annotations

import argparse
import sys

from artifact_trust.config import Settings
from artifact_trust.pipeline import run_pipeline
from artifact_trust.queue import FileQueue


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--job-id", required=True)
    arguments = parser.parse_args()
    settings = Settings.from_env()
    queue = FileQueue(settings)
    record = queue.get(arguments.job_id)
    if record is None or record.state != "running":
        print("invalid running job", file=sys.stderr)
        return 2
    output = settings.work_root / "results" / record.id
    try:
        run_pipeline(record.request.source, output, settings, record.request.policy_engine)
    except Exception as exc:
        print(f"{type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
