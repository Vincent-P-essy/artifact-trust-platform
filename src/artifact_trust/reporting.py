"""Self-contained, escaped HTML report rendering."""

from __future__ import annotations

from html import escape
from pathlib import Path

from artifact_trust.models import PipelineReport


def render_html(report: PipelineReport, destination: Path) -> None:
    decision = escape(report.policy.decision.value)
    rows = (
        "\n".join(
            "<tr>"
            f"<td>{escape(finding.severity.value)}</td>"
            f"<td>{escape(finding.category)}</td>"
            f"<td>{escape(finding.title)}</td>"
            f"<td><code>{escape(finding.subject)}</code></td>"
            "</tr>"
            for finding in report.findings
        )
        or '<tr><td colspan="4">No findings</td></tr>'
    )
    reasons = "".join(f"<li>{escape(reason)}</li>" for reason in report.policy.reasons)
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>Artifact Trust Report</title>
  <style>
    :root {{ color-scheme: light dark; font-family: system-ui, sans-serif; }}
    body {{ max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
    .decision {{ border: 2px solid currentColor; padding: 1rem; border-radius: .5rem; }}
    .ALLOW {{ color: #17803d; }} .QUARANTINE {{ color: #b36b00; }} .REJECT {{ color: #c92a2a; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #8886; padding: .65rem; text-align: left; vertical-align: top; }}
    code {{ overflow-wrap: anywhere; }}
    dl {{ display: grid; grid-template-columns: max-content 1fr; gap: .4rem 1rem; }}
  </style>
</head>
<body>
  <h1>Artifact Trust Report</h1>
  <section class="decision {decision}">
    <h2>{decision}</h2><ul>{reasons}</ul>
  </section>
  <h2>Evidence</h2>
  <dl>
    <dt>Report</dt><dd><code>{escape(report.report_id)}</code></dd>
    <dt>Source</dt><dd>{escape(str(report.source["location"]))}</dd>
    <dt>Source digest</dt><dd><code>{escape(str(report.source["digest_sha256"]))}</code></dd>
    <dt>Artifact digest</dt><dd><code>{escape(str(report.artifact["digest_sha256"]))}</code></dd>
    <dt>Signature</dt><dd>{"valid" if report.verification.signature_valid else "invalid"}</dd>
    <dt>Artifact binding</dt><dd>{"valid" if report.verification.artifact_digest_valid else "invalid"}</dd>
    <dt>Risk score</dt><dd>{report.risk.score}/100 ({escape(report.risk.grade)})</dd>
    <dt>Policy engine</dt><dd>{escape(report.policy.engine)}</dd>
  </dl>
  <h2>Dependencies</h2>
  <p>{len(report.manifests.components)} components, {len(report.manifests.edges)} edges,
  {len(report.manifests.unpinned_dependencies)} unpinned.</p>
  <h2>Findings</h2>
  <table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Subject</th></tr></thead>
  <tbody>{rows}</tbody></table>
  <p>This report is self-contained and loads no remote resources.</p>
</body>
</html>
"""
    destination.write_text(html, encoding="utf-8")
