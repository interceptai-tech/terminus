# --- Builder: install the app into a self-contained venv ---------------------
# build-essential lives ONLY here (GAPS M3): the runtime image ships no
# compiler toolchain. The install is non-editable and WITHOUT the [dev] extra,
# so pytest/mypy/ruff never reach the runtime image either.
FROM python:3.13-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir uv && \
    uv venv /opt/venv && \
    uv pip install --python /opt/venv/bin/python --no-cache .

# --- Runtime: minimal, non-root -----------------------------------------------
FROM python:3.13-slim

# netcat: wait-for-redis.sh; curl: the compose healthcheck. Nothing else.
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-traditional \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user with a writable HOME outside /app. App files below stay
# root-owned and world-readable ON PURPOSE: the process can read and execute
# but cannot modify its own code or config.
RUN useradd --system --create-home terminus

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY wait-for-redis.sh /app/
COPY examples/ ./examples/
RUN chmod +x /app/wait-for-redis.sh

ENV PATH="/opt/venv/bin:$PATH"

USER terminus
EXPOSE 8000

CMD ["./wait-for-redis.sh", "python", "-m", "uvicorn", "terminus.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
