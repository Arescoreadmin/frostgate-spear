# Frost Gate Spear - Production Dockerfile
# Multi-stage build for minimal image size

# Build stage
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip wheel setuptools
RUN pip install --no-cache-dir .

# Copy source code and install
COPY src/ src/
COPY policy/ policy/
COPY mls_rings/ mls_rings/
COPY adversary_personas/ adversary_personas/
COPY fl_rings/ fl_rings/
COPY scenarios/ scenarios/
COPY configs/ configs/

# Production stage
FROM python:3.11-slim as production

# Security: Run as non-root user
RUN groupadd -r frostgate && useradd -r -g frostgate frostgate

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application files
COPY --from=builder /build/src /app/src
COPY --from=builder /build/policy /app/policy
COPY --from=builder /build/mls_rings /app/mls_rings
COPY --from=builder /build/adversary_personas /app/adversary_personas
COPY --from=builder /build/fl_rings /app/fl_rings
COPY --from=builder /build/scenarios /app/scenarios
COPY --from=builder /build/configs /app/configs

# Create necessary directories
RUN mkdir -p /var/log/frostgate/forensics && \
    chown -R frostgate:frostgate /var/log/frostgate && \
    chown -R frostgate:frostgate /app

# Switch to non-root user
USER frostgate

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FROSTGATE_CONFIG=/app/configs/default.yaml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# Expose port
EXPOSE 8080

# Default command
CMD ["python", "-m", "src.cli", "server", "--host", "0.0.0.0", "--port", "8080"]
