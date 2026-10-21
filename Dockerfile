FROM registry.access.redhat.com/ubi10/python-312-minimal:latest

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy application code and install
COPY src/ ./src/
COPY run_server.py ./
RUN uv sync --frozen --no-dev --no-editable --compile-bytecode

# Default environment for containerized HTTP mode
ENV MCP_TRANSPORT=http
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000

# Read-only filesystem hardening
ENV DATA_DIR=/data
ENV TMPDIR=/tmp
ENV UV_NO_CACHE=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Pre-create the default DATA_DIR owned by the runtime user, so a fresh named
# volume mounted there inherits writable ownership (startup creates imports/).
USER root
RUN mkdir -p /data && chown 1001:0 /data && chmod 0770 /data
# Image runs as non-root user (UID 1001)
USER 1001

# No database path argument: every tenant's database, the default one included,
# resolves under $DATA_DIR. A hardcoded path here goes stale whenever DATA_DIR
# changes, and the in-process daily sync used to read it as a tenant filter.
ENTRYPOINT ["uv", "run", "--no-sync", "run_server.py"]
