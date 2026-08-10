# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM ghcr.io/astral-sh/uv:0.11.23@sha256:d0a0a753ab981624b49c97abc98821c1c09f4ca69d1ef5cee69c501be3d88479 AS uv

FROM python:3.14.0-slim-bookworm@sha256:d13fa0424035d290decef3d575cea23d1b7d5952cdf429df8f5542c71e961576 AS builder
COPY --from=uv /uv /uvx /usr/local/bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project
COPY README.md LICENSE ./
COPY src ./src
COPY fixtures ./fixtures
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

FROM python:3.14.0-slim-bookworm@sha256:d13fa0424035d290decef3d575cea23d1b7d5952cdf429df8f5542c71e961576 AS runtime
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ATP_WORK_ROOT=/var/lib/artifact-trust \
    ATP_FIXTURES_ROOT=/app/fixtures \
    ATP_ALLOWED_LOCAL_ROOTS=/app/fixtures \
    ATP_ALLOWED_GIT_HOSTS=github.com \
    ATP_ALLOW_NETWORK=0
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10000 artifacttrust \
    && groupadd --gid 10002 artifactworker \
    && useradd --uid 10001 --gid 10000 --no-create-home --home-dir /nonexistent \
       --shell /usr/sbin/nologin artifactapi \
    && useradd --uid 10002 --gid 10000 --no-create-home --home-dir /nonexistent \
       --shell /usr/sbin/nologin artifactworker \
    && usermod --append --groups artifactworker artifactworker \
    && install -d -o root -g artifacttrust -m 0755 /var/lib/artifact-trust \
    && install -d -o artifactapi -g artifacttrust -m 0770 /var/lib/artifact-trust/pending \
    && install -d -o artifactworker -g artifactworker -m 0755 \
       /var/lib/artifact-trust/running \
       /var/lib/artifact-trust/completed \
       /var/lib/artifact-trust/failed \
    && install -d -o artifactworker -g artifacttrust -m 0770 /var/lib/artifact-trust/results \
    && install -d -o artifactworker -g artifactworker -m 0700 /var/lib/artifact-trust/sources \
    && install -d -o artifactworker -g artifacttrust -m 0700 /var/lib/artifact-trust-private \
    && install -d -o artifactworker -g artifacttrust -m 0770 /var/lib/artifact-trust-public
WORKDIR /app
COPY --from=builder --chown=10001:10000 /app/.venv /app/.venv
COPY --chown=10001:10000 fixtures /app/fixtures
USER 10001:10000
EXPOSE 8000
CMD ["artifact-trust", "serve", "--host", "0.0.0.0", "--port", "8000"]
