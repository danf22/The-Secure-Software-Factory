"""
Remediated FastAPI Microservice for the organization Secure Software Factory.

This is the secure version of the vulnerable seed application, demonstrating
proper security practices for the Green Demo pipeline run.

Security improvements over the vulnerable version:
1. Secrets loaded from environment variables (never hardcoded)
2. Parameterized database queries (no SQL injection)
3. No command injection — subprocess uses list args, no shell=True
4. Input validation with Pydantic models
5. Dependencies pinned to patched versions with no known CVEs
"""

import os
import sqlite3
import subprocess
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

app = FastAPI(
    title="Treasury Service (Remediated)",
    description="Secure microservice for the organization treasury operations",
    version="1.0.0",
)

# =============================================================================
# SECURITY FIX #1: Secrets loaded from environment variables
# The vulnerable version had secrets hardcoded directly in source code.
# This version reads them from the environment at runtime, ensuring secrets
# are never committed to version control.
# =============================================================================
API_KEY = os.environ.get("APP_API_KEY", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./app.db")
SECRET_TOKEN = os.environ.get("SECRET_TOKEN", "")


# =============================================================================
# Input validation models using Pydantic
# The vulnerable version accepted raw strings without validation.
# =============================================================================
class TransactionQuery(BaseModel):
    """Validated input for transaction lookups."""

    user_id: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        """Ensure user_id contains only safe characters."""
        if not v.isalnum() and not all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in v):
            raise ValueError("user_id must be alphanumeric with optional underscores/hyphens")
        return v


class HealthCheckResponse(BaseModel):
    """Response model for health check endpoint."""

    status: str
    version: str


class TransactionResponse(BaseModel):
    """Response model for transaction queries."""

    user_id: str
    transactions: list[dict]


class FileInfoResponse(BaseModel):
    """Response model for file info endpoint."""

    filename: str
    line_count: int


# =============================================================================
# Database helper with parameterized queries
# =============================================================================
def get_db_connection() -> sqlite3.Connection:
    """Create a database connection with secure defaults."""
    db_path = DATABASE_URL.replace("sqlite:///", "")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the database with the transactions table."""
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                amount REAL NOT NULL,
                currency TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


# =============================================================================
# API Endpoints
# =============================================================================


@app.on_event("startup")
async def startup_event() -> None:
    """Initialize database on application startup."""
    init_db()


@app.get("/health", response_model=HealthCheckResponse)
async def health_check() -> HealthCheckResponse:
    """Health check endpoint."""
    return HealthCheckResponse(status="healthy", version="1.0.0")


@app.get("/transactions", response_model=TransactionResponse)
async def get_transactions(
    user_id: str = Query(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="User ID to query transactions for",
    ),
) -> TransactionResponse:
    """
    Retrieve transactions for a given user.

    SECURITY FIX #2: Parameterized queries prevent SQL injection.
    The vulnerable version used f-string formatting:
        query = f"SELECT * FROM transactions WHERE user_id = '{user_id}'"
    This version uses parameterized queries with placeholders.
    """
    conn = get_db_connection()
    try:
        # SECURE: Using parameterized query with ? placeholder
        # The database driver handles escaping, preventing SQL injection
        cursor = conn.execute(
            "SELECT id, user_id, amount, currency, timestamp FROM transactions WHERE user_id = ?",
            (user_id,),
        )
        rows = cursor.fetchall()
        transactions = [
            {
                "id": row["id"],
                "user_id": row["user_id"],
                "amount": row["amount"],
                "currency": row["currency"],
                "timestamp": row["timestamp"],
            }
            for row in rows
        ]
    finally:
        conn.close()

    return TransactionResponse(user_id=user_id, transactions=transactions)


@app.get("/file-info", response_model=FileInfoResponse)
async def get_file_info(
    filename: str = Query(
        ...,
        min_length=1,
        max_length=255,
        pattern=r"^[a-zA-Z0-9._-]+$",
        description="Filename to get line count for (no path separators allowed)",
    ),
) -> FileInfoResponse:
    """
    Get line count for a file in the data directory.

    SECURITY FIX #3: No command injection.
    The vulnerable version used:
        result = subprocess.run(f"wc -l {filename}", shell=True, ...)
    This version:
    - Uses subprocess with a list of arguments (no shell=True)
    - Validates filename to prevent path traversal
    - Restricts to a safe data directory
    """
    # Validate: no path traversal characters
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")

    # Restrict file access to a safe data directory
    safe_dir = os.path.join(os.path.dirname(__file__), "data")
    file_path = os.path.join(safe_dir, filename)

    # Verify resolved path is within safe directory (prevent symlink attacks)
    real_safe_dir = os.path.realpath(safe_dir)
    real_file_path = os.path.realpath(file_path)
    if not real_file_path.startswith(real_safe_dir):
        raise HTTPException(status_code=400, detail="Access denied: file outside allowed directory")

    if not os.path.isfile(real_file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # SECURE: Using subprocess with list args — no shell=True, no string interpolation
    # Each argument is passed separately, preventing shell metacharacter injection
    result = subprocess.run(
        ["wc", "-l", real_file_path],
        capture_output=True,
        text=True,
        timeout=10,
    )

    if result.returncode != 0:
        raise HTTPException(status_code=500, detail="Failed to process file")

    # Parse wc output (format: "   42 /path/to/file")
    line_count = int(result.stdout.strip().split()[0])

    return FileInfoResponse(filename=filename, line_count=line_count)


@app.get("/exchange-rate")
async def get_exchange_rate(
    base: str = Query(
        ...,
        min_length=3,
        max_length=3,
        pattern=r"^[A-Z]{3}$",
        description="Base currency code (3 uppercase letters)",
    ),
    target: str = Query(
        ...,
        min_length=3,
        max_length=3,
        pattern=r"^[A-Z]{3}$",
        description="Target currency code (3 uppercase letters)",
    ),
) -> dict:
    """
    Get exchange rate between two currencies.

    SECURITY FIX #1 (continued): API key for external service is loaded
    from environment variables, not hardcoded in source code.
    """
    if not API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Exchange rate service not configured (missing API key)",
        )

    # In production, this would call an external FX API using the secure API key
    # For demonstration, return a mock rate
    supported_pairs = {
        ("USD", "MXN"): 17.15,
        ("MXN", "USD"): 0.058,
    }

    rate = supported_pairs.get((base, target))
    if rate is None:
        raise HTTPException(status_code=404, detail=f"Exchange rate not available for {base}/{target}")

    return {"base": base, "target": target, "rate": rate}
