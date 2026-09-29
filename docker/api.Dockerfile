# syntax=docker/dockerfile:1
# One image, three roles (chosen by the command in docker-compose.yml):
#   api     uvicorn api.main:create_app --factory
#   worker  celery -A api.jobs.celery_app worker
#   target  uvicorn targets.vulnerable_app.main:app   (the deliberately vulnerable demo app)
# Build context: the repository root.

FROM python:3.11-slim AS wheel
WORKDIR /src
RUN pip install --no-cache-dir --disable-pip-version-check build
COPY pyproject.toml README.md LICENSE ./
COPY scanner ./scanner
COPY api ./api
COPY targets ./targets
COPY probes ./probes
RUN python -m build --wheel --outdir /dist

FROM python:3.11-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10001 --create-home --home-dir /home/llmscan llmscan
COPY --from=wheel /dist/*.whl /tmp/wheels/
RUN pip install "$(ls /tmp/wheels/*.whl)[server,celery,postgres]" && rm -rf /tmp/wheels
WORKDIR /home/llmscan
USER llmscan
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
