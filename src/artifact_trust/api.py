"""FastAPI control plane. Analysis is delegated to a separate worker queue."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from artifact_trust import __version__
from artifact_trust.config import PACKAGE_ROOT, Settings
from artifact_trust.errors import JobError, SourceValidationError
from artifact_trust.models import JobRecord, JobRequest
from artifact_trust.queue import FileQueue
from artifact_trust.source import FIXTURE_RE, validate_git_source


def create_app(settings: Settings | None = None) -> FastAPI:
    configuration = settings or Settings.from_env()
    configuration.ensure_directories()
    queue = FileQueue(configuration)
    app = FastAPI(
        title="Artifact Trust Platform",
        version=__version__,
        description="Supply-chain evidence control plane; workers perform all analysis.",
    )
    app.mount(
        "/static",
        StaticFiles(directory=PACKAGE_ROOT / "static", check_dir=True),
        name="static",
    )

    @app.get("/healthz")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/fixtures")
    def fixtures() -> dict[str, list[str]]:
        names = (
            [
                path.name
                for path in configuration.fixtures_root.iterdir()
                if path.is_dir() and FIXTURE_RE.fullmatch(path.name)
            ]
            if configuration.fixtures_root.is_dir()
            else []
        )
        return {"fixtures": sorted(names)}

    @app.post("/api/v1/jobs", response_model=JobRecord, status_code=202)
    def submit(request: JobRequest) -> JobRecord:
        try:
            if request.source.kind == "fixture":
                if not FIXTURE_RE.fullmatch(request.source.location):
                    raise SourceValidationError("invalid fixture name")
                path = (configuration.fixtures_root / request.source.location).resolve()
                if not path.is_relative_to(configuration.fixtures_root) or not path.is_dir():
                    raise SourceValidationError("unknown fixture")
            elif request.source.kind == "git":
                validate_git_source(request.source.location, request.source.commit, configuration)
        except SourceValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return queue.enqueue(request)

    @app.get("/api/v1/jobs", response_model=list[JobRecord])
    def list_jobs(limit: int = Query(default=50, ge=1, le=200)) -> list[JobRecord]:
        return queue.list(limit)

    @app.get("/api/v1/jobs/{job_id}", response_model=JobRecord)
    def get_job(job_id: str) -> JobRecord:
        record = queue.get(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="job not found")
        return record

    @app.get("/api/v1/jobs/{job_id}/report")
    def get_report(job_id: str) -> dict[str, object]:
        try:
            return queue.result(job_id)
        except JobError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/jobs/{job_id}/report.html", response_class=FileResponse)
    def get_html_report(job_id: str) -> FileResponse:
        record = queue.get(job_id)
        if record is None or record.state != "completed" or not record.result_path:
            raise HTTPException(status_code=409, detail="job has no completed result")
        report_path = (configuration.work_root / record.result_path).resolve()
        html_path = report_path.with_name("report.html")
        if not html_path.is_relative_to(configuration.work_root) or not html_path.is_file():
            raise HTTPException(status_code=404, detail="HTML report not found")
        return FileResponse(html_path, media_type="text/html")

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> HTMLResponse:
        content = (PACKAGE_ROOT / "static" / "dashboard.html").read_text(encoding="utf-8")
        return HTMLResponse(
            content,
            headers={
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; style-src 'self'; "
                    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
                ),
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )

    return app


app = create_app()
