# =============================================================================
# INTENTIONALLY INSECURE DOCKERFILE — FOR DEMONSTRATION PURPOSES ONLY
# =============================================================================
# This Dockerfile is part of the Vulnerable Seed application used to validate
# the Secure Software Factory pipeline. It contains deliberate security issues:
#
#   1. Uses an older, full Python base image with known CVEs
#   2. Runs the application as root (no USER directive)
#   3. No health check, no minimal base, no multi-stage build
#
# These issues will be detected by:
#   - Trivy container scanner (CVEs in base image and dependencies)
#   - OPA/Conftest policy gate (container running as root)
#
# See remediated-app/Dockerfile for the secure version.
# =============================================================================

# Full python:3.9 image has many more CVEs than slim/alpine variants
FROM python:3.9

# No USER directive — application runs as root (policy violation: no_root_container)

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the application port
EXPOSE 8000

# Run the application as root (insecure)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
