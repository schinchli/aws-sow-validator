# Multi-stage, Python 3.12, ARM64 — matches the platform AgentCore Runtime uses.
#
# Build context is the PROJECT ROOT (see infrastructure/agentcore/agentcore.json's
# `buildContextPath`), not source/agent/, because the deterministic core
# reads config/data/*.yaml and config/rules/*.yaml as siblings of source/, not
# underneath it. Paths below are relative to that root, not this file's own
# directory.
FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.12-slim AS builder

WORKDIR /build
COPY source/agent/requirements.txt .
RUN pip install --no-cache-dir --target /deps -r requirements.txt

FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.12-slim

WORKDIR /app
COPY --from=builder /deps /usr/local/lib/python3.12/site-packages
COPY source/agent/ /app/

# Data and rule packs live outside the agent package so they can be edited
# without touching Python. POC_VALIDATOR_ROOT=/app, and catalog.py resolves
# them at ROOT/config/data and ROOT/config/rules, so they must land there.
COPY config/data/ /app/config/data/
COPY config/rules/ /app/config/rules/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POC_VALIDATOR_ROOT=/app

# Nothing here needs root at runtime: the app binds 8080 and only reads
# /app. A fixed high UID keeps the image portable across runtimes.
# COPY preserves the build host's file modes, so a contributor with a
# restrictive umask ships files uid 10001 cannot read (import-time
# PermissionError) — normalise read bits before dropping root.
RUN chmod -R a+rX /app
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser
USER 10001

EXPOSE 8080
CMD ["python", "main.py"]
