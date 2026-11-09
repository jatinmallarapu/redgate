FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY redgate ./redgate
RUN python -m pip install --no-cache-dir . \
    && mkdir /runs \
    && chown 10001:10001 /runs

USER 10001:10001
ENV REDGATE_RUN_DIR=/runs PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["redgate"]
