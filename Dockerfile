FROM python:3.14-slim

ARG GUNICORN_WORKERS
ARG LISTEN_ADDR
ARG LISTEN_PORT
ENV GUNICORN_WORKERS=${GUNICORN_WORKERS}
ENV LISTEN_ADDR=${LISTEN_ADDR}
ENV LISTEN_PORT=${LISTEN_PORT}

RUN apt-get update \
    && apt-get install -y --no-install-recommends mtr-tiny \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 appuser \
    && useradd -u 1000 -g appuser -M -s /usr/sbin/nologin appuser

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache

COPY app.py ./
COPY templates ./templates
COPY static ./static

ENV PATH="/app/.venv/bin:$PATH"

RUN mkdir -p /app/logs \
&& chown -R appuser:appuser /app

USER appuser

EXPOSE ${LISTEN_PORT}

CMD ["sh", "-c", "exec gunicorn --bind ${LISTEN_ADDR}:${LISTEN_PORT} --workers ${GUNICORN_WORKERS} --capture-output --access-logfile /app/logs/access.log --error-logfile /app/logs/access.log app:app"]
