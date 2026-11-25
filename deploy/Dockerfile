FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN useradd -m -u 1000 -s /bin/bash hunter

WORKDIR /app

# Install uv for reproducible locked dependency builds
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Install dependencies from uv.lock before copying source for better layer caching
COPY pyproject.toml README.md uv.lock ./
COPY hecate_agent/ ./hecate_agent/

ENV PATH="/app/.venv/bin:$PATH"
RUN uv sync --locked --all-extras --no-dev

# Persistent workspace for hunt data (mounted as a volume)
RUN mkdir -p /workspace && chown hunter:hunter /workspace

USER hunter
WORKDIR /workspace

CMD ["/bin/bash"]
