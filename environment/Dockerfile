FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends bash \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1000 --shell /bin/bash agent

WORKDIR /app
COPY --chown=agent:agent app/ /app/
RUN chown -R agent:agent /app
