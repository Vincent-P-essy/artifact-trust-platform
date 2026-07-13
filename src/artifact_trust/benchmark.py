"""Repeatable local performance measurement harness."""

from __future__ import annotations

import shutil
import statistics
import tempfile
import time
from math import ceil
from pathlib import Path
from typing import Any

from artifact_trust.config import Settings
from artifact_trust.models import SourceSpec
from artifact_trust.pipeline import run_pipeline


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, ceil(len(ordered) * percentile) - 1))
    return ordered[index]


def benchmark_pipeline(
    source_spec: SourceSpec,
    settings: Settings,
    iterations: int = 10,
    warmups: int = 1,
) -> dict[str, Any]:
    if not 1 <= iterations <= 100:
        raise ValueError("iterations must be between 1 and 100")
    if not 0 <= warmups <= 20:
        raise ValueError("warmups must be between 0 and 20")
    root = Path(tempfile.mkdtemp(prefix="artifact-trust-benchmark-"))
    durations: list[float] = []
    last_report = None
    try:
        for index in range(warmups + iterations):
            output = root / f"run-{index}"
            started = time.perf_counter_ns()
            last_report = run_pipeline(source_spec, output, settings, "fallback")
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            if index >= warmups:
                durations.append(elapsed_ms)
        assert last_report is not None
        return {
            "schema_version": "1.0",
            "iterations": iterations,
            "warmups": warmups,
            "p50_ms": round(_percentile(durations, 0.50), 3),
            "p95_ms": round(_percentile(durations, 0.95), 3),
            "mean_ms": round(statistics.fmean(durations), 3),
            "min_ms": round(min(durations), 3),
            "max_ms": round(max(durations), 3),
            "component_count": len(last_report.manifests.components),
            "finding_count": len(last_report.findings),
            "decision": last_report.policy.decision.value,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)
