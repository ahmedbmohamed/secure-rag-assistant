FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SRAG_HOME=/app \
    SRAG_EMBED_CACHE_DIR=/app/models

WORKDIR /app
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Download the embedding model at build time, so the running container needs no internet access.
RUN python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5', cache_dir='/app/models')"

COPY pyproject.toml .
COPY src ./src
RUN pip install --no-deps .

COPY api ./api
COPY web ./web
COPY data ./data
COPY scripts ./scripts
COPY eval ./eval

RUN mkdir -p /app/logs /app/index /app/config && chown -R app:app /app/logs /app/index /app/config
ENV HF_HUB_OFFLINE=1
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
