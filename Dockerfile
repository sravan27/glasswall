FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GLASSWALL_DB_PATH=/data/glasswall.db \
    GLASSWALL_CACHE_DIR=/data/cache

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

VOLUME ["/data", "/workspace"]
EXPOSE 8080

CMD ["glasswall", "serve", "--host", "0.0.0.0", "--port", "8080"]

