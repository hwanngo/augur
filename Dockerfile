# ── Stage 1: Build the React SPA ─────────────────────────────────────────────
FROM node:24-slim AS frontend

WORKDIR /app/frontend

# Install pnpm (matches frontend/package.json "packageManager")
RUN npm install -g pnpm@12.9.1

# Copy lockfile + manifest first for layer caching
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./

RUN pnpm install --frozen-lockfile

# Copy source and build
COPY frontend/ .
RUN pnpm build

# ── Stage 2: Python runtime ───────────────────────────────────────────────────
# Augur API/dashboard image — uv-managed, Python 3.14.
FROM python:3.14-slim AS runtime

# uv binary (pinned to a specific version for reproducible builds)
COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    AUGUR_LOGS=sample_data/demo.jsonl

WORKDIR /app

# 1) Dependency layer (cached unless pyproject.toml / uv.lock change).
#    Install the Neo4j extra so the image can use either backend.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --extra neo4j

# 2) Project sources + the data the engine reads at runtime.
COPY src ./src
COPY scenarios ./scenarios
COPY sample_data ./sample_data
RUN uv sync --frozen --extra neo4j

# 3) Copy the built React SPA from the frontend stage.
COPY --from=frontend /app/frontend/dist ./frontend/dist

# Run as an unprivileged user. /data is pre-created and owned so that a freshly
# created named volume mounted there inherits this ownership (Docker copies the
# image dir's ownership into an empty volume on first mount).
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin augur \
    && mkdir -p /data \
    && chown -R augur:augur /app /data
USER augur

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/ready').status==200 else 1)"]

# Serve the FastAPI app (bind 0.0.0.0 so it is reachable outside the container).
CMD ["uv", "run", "--frozen", "--extra", "neo4j", \
     "uvicorn", "augur.api.app:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000"]
