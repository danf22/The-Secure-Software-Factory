# =============================================================================
# SECURE DOCKERFILE — Remediated version demonstrating container security best
# practices for the Secure Software Factory green demonstration.
# =============================================================================
# This Dockerfile resolves all security issues present in vulnerable-app/Dockerfile:
#
#   1. Uses minimal base image (python:3.12-slim) to reduce attack surface
#   2. Creates and runs as a non-root user (appuser)
#   3. Uses multi-stage build to exclude build tools from final image
#   4. Pins package versions for reproducibility
#   5. Sets proper file permissions (least privilege)
#   6. Includes a HEALTHCHECK for container orchestration
#   7. Does not store secrets in the image
#
# Security scanning results (expected):
#   - Trivy container scan: 0 critical/high CVEs
#   - OPA/Conftest policy gate: passes no_root_container policy
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder — install dependencies in a throwaway image
# SECURITY: Build tools and pip cache never reach the final image, reducing
# attack surface and image size.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Copy only requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install dependencies into a virtual environment so we can copy just the
# venv to the runtime stage (no system-wide pip pollution)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# SECURITY: --no-cache-dir prevents pip from storing downloaded packages,
# reducing image size and preventing information leakage
RUN pip install --no-cache-dir --upgrade pip==24.0 \
    && pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: Runtime — minimal image with only what's needed to run the app
# SECURITY: The final image contains no compilers, build headers, or pip cache.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# SECURITY: Add metadata labels for traceability and provenance
LABEL maintainer="Security Engineering <security@company.com>"
LABEL org.opencontainers.image.title="remediated-app"
LABEL org.opencontainers.image.description="Secure FastAPI microservice for the organization green demo"
LABEL org.opencontainers.image.source="https://github.com/org/secure-software-factory"

# SECURITY: Set environment variables for Python best practices in containers
# - PYTHONDONTWRITEBYTECODE: Prevents .pyc file generation (reduces image size)
# - PYTHONUNBUFFERED: Ensures logs are flushed immediately for observability
# - PYTHONFAULTHANDLER: Enables traceback on segfaults for debugging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

WORKDIR /app

# SECURITY: Create a non-root user and group with specific UID/GID.
# Running as non-root prevents container escape privilege escalation attacks
# and satisfies the no_root_container policy gate.
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --shell /sbin/nologin --create-home appuser

# Copy the virtual environment from the builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code with explicit ownership by the non-root user
# SECURITY: Files are owned by appuser, preventing modification by other
# processes and enforcing least privilege file access.
COPY --chown=appuser:appgroup . .

# SECURITY: Remove write permissions from application files.
# The application should not need to modify its own source code at runtime.
RUN chmod -R a-w /app \
    && chmod -R u+r /app

# Expose the application port (documentation only, doesn't publish)
EXPOSE 8000

# SECURITY: Switch to the non-root user BEFORE running the application.
# This is the critical directive that satisfies the no_root_container policy.
USER appuser

# HEALTHCHECK: Allows orchestrators (Docker Compose, ECS, Kubernetes) to
# detect unhealthy containers and restart them automatically.
# - interval: check every 30s
# - timeout: fail if check takes longer than 10s
# - retries: mark unhealthy after 3 consecutive failures
# - start-period: give the app 10s to start before checking
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=10s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]

# Run the application with minimal privileges
# SECURITY: Using exec form (JSON array) to avoid shell injection vectors
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
