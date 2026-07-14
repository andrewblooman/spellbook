# syntax=docker/dockerfile:1

# --- Stage 1: build the Vite/React SPA -> web/dist ------------------------
FROM node:20-alpine AS web
WORKDIR /app
# Install deps first (cached unless the manifests change).
COPY web/package.json web/package-lock.json* web/
RUN npm --prefix web install
COPY web/ web/
RUN npm --prefix web run build

# --- Stage 2: control-plane runtime (default target) ----------------------
FROM python:3.14-slim AS runtime
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# psycopg[binary] bundles libpq, so no apt build deps are required.
COPY pyproject.toml ./
COPY spellbook/ spellbook/
COPY --from=web /app/web/dist web/dist

# Editable install keeps the package rooted at /app, so create_app resolves the
# built SPA at /app/web/dist (it locates web/dist relative to the package file).
RUN pip install -e .

EXPOSE 8000
CMD ["python", "-m", "spellbook.control.server"]

# --- Stage 3: agent-worker (runtime + Node.js + Claude Code CLI) -----------
# The Claude Agent SDK drives the `claude` Code CLI, which needs Node.js, so the
# worker image adds it. Build with `--target worker`. Runs the in-VPC pull loop;
# needs no inbound port (it claims work from the control plane).
FROM runtime AS worker
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && npm install -g @anthropic-ai/claude-code \
 && apt-get purge -y --auto-remove gnupg curl \
 && rm -rf /var/lib/apt/lists/*
CMD ["python", "-m", "spellbook.worker.server"]
