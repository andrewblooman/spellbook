# syntax=docker/dockerfile:1

# --- Stage 1: build the Vite/React SPA -> web/dist ------------------------
FROM node:20-alpine AS web
WORKDIR /app
# Install deps first (cached unless the manifests change).
COPY web/package.json web/package-lock.json* web/
RUN npm --prefix web install
COPY web/ web/
RUN npm --prefix web run build

# --- Stage 2: python runtime (serves control plane OR a runner) -----------
# One image, two roles: docker-compose overrides `command` per service.
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
