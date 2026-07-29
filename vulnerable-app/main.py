"""
Vulnerable FastAPI Microservice - Secure Software Factory Demo
===================================================================

WARNING: This application contains INTENTIONAL security vulnerabilities
for demonstration purposes. It is designed to trigger findings in:
- Secrets scanners (Gitleaks)
- SAST scanners (Semgrep)
- SCA scanners (Trivy/Dependabot via requirements.txt)

DO NOT deploy this application in any environment.
"""

import os
import sqlite3
import subprocess

from fastapi import FastAPI, HTTPException, Query

# =============================================================================
# VULNERABILITY 1: Hardcoded secrets in source code
# Purpose: Triggers Gitleaks / secrets scanner detection
# =============================================================================

# INTENTIONAL: Hardcoded API key (secrets scanner demonstration)
API_KEY = "sk_live_51J3kHRGnbFqXKYowqpGQrTW8NdZ0fvhJLqE9kR7x"  # noqa: S105

# INTENTIONAL: Hardcoded database credentials (secrets scanner demonstration)
DATABASE_PASSWORD = "super_secret_password_123!"  # noqa: S105

# INTENTIONAL: Hardcoded AWS credentials (secrets scanner demonstration)
AWS_ACCESS_KEY_ID = "AKIAQWERTYUIOP12NXYZ"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI7K9MDENG+bPxRfiCYzEXAMPLEKEY"  # noqa: S105

# INTENTIONAL: Hardcoded JWT signing secret (secrets scanner demonstration)
JWT_SECRET = "my-super-secret-jwt-signing-key-do-not-share"  # noqa: S105


# =============================================================================
# Application Setup
# =============================================================================

app = FastAPI(
    title="Treasury Service (Vulnerable Demo)",
    description="Intentionally vulnerable microservice for security scanning demonstration",
    version="0.1.0",
)

# In-memory SQLite database for demonstration
DB_PATH = ":memory:"


def get_db_connection():
    """Create a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'MXN',
            status TEXT DEFAULT 'pending'
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )"""
    )
    # Insert sample data
    conn.execute(
        "INSERT OR IGNORE INTO users (username, email, role) VALUES (?, ?, ?)",
        ("admin", "admin@company.mx", "admin"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, email, role) VALUES (?, ?, ?)",
        ("trader1", "trader1@company.mx", "user"),
    )
    conn.commit()
    return conn


# =============================================================================
# VULNERABILITY 2: SQL Injection
# Purpose: Triggers Semgrep / SAST scanner detection
# =============================================================================


@app.get("/api/v1/users/search")
def search_users(username: str = Query(..., description="Username to search for")):
    """
    Search for users by username.

    INTENTIONAL VULNERABILITY: SQL Injection via string formatting.
    User input is directly interpolated into the SQL query without
    parameterization, allowing an attacker to inject arbitrary SQL.

    Example exploit: ?username=' OR '1'='1
    """
    conn = get_db_connection()
    try:
        # INTENTIONAL: SQL injection via string formatting (SAST demonstration)
        query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
        cursor = conn.execute(query)
        results = cursor.fetchall()

        if not results:
            raise HTTPException(status_code=404, detail="User not found")

        return {
            "users": [
                {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}
                for row in results
            ]
        }
    finally:
        conn.close()


@app.get("/api/v1/transactions/query")
def query_transactions(
    status: str = Query("pending", description="Transaction status filter"),
    currency: str = Query("MXN", description="Currency filter"),
):
    """
    Query transactions by status and currency.

    INTENTIONAL VULNERABILITY: SQL Injection via string concatenation.
    Multiple user inputs concatenated directly into query string.

    Example exploit: ?status=pending' UNION SELECT id, username, email, role, '', '' FROM users--
    """
    conn = get_db_connection()
    try:
        # INTENTIONAL: SQL injection via string concatenation (SAST demonstration)
        query = (
            "SELECT * FROM transactions WHERE status = '"
            + status
            + "' AND currency = '"
            + currency
            + "'"
        )
        cursor = conn.execute(query)
        results = cursor.fetchall()

        return {
            "transactions": [
                {
                    "id": row[0],
                    "sender": row[1],
                    "receiver": row[2],
                    "amount": row[3],
                    "currency": row[4],
                    "status": row[5],
                }
                for row in results
            ]
        }
    finally:
        conn.close()


# =============================================================================
# VULNERABILITY 3: Command Injection
# Purpose: Triggers Semgrep / SAST scanner detection
# =============================================================================


@app.get("/api/v1/system/ping")
def ping_host(host: str = Query(..., description="Host to ping")):
    """
    Ping a host to check connectivity.

    INTENTIONAL VULNERABILITY: Command injection via subprocess with shell=True.
    User input is passed directly to a shell command without sanitization,
    allowing an attacker to execute arbitrary system commands.

    Example exploit: ?host=127.0.0.1; cat /etc/passwd
    """
    # INTENTIONAL: Command injection via subprocess shell=True (SAST demonstration)
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,  # noqa: S602
        capture_output=True,
        text=True,
        timeout=10,
    )

    return {
        "host": host,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


@app.get("/api/v1/system/lookup")
def dns_lookup(domain: str = Query(..., description="Domain to resolve")):
    """
    Perform DNS lookup for a domain.

    INTENTIONAL VULNERABILITY: Command injection via os.popen.
    User input is interpolated directly into an OS command.

    Example exploit: ?domain=example.com; whoami
    """
    # INTENTIONAL: Command injection via os.popen (SAST demonstration)
    output = os.popen(f"nslookup {domain}").read()  # noqa: S605

    return {"domain": domain, "result": output}


# =============================================================================
# Legitimate endpoints (for application realism)
# =============================================================================


@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "0.1.0"}


@app.get("/api/v1/rates")
def get_exchange_rates():
    """Get current FX rates (mock data)."""
    return {
        "base": "USD",
        "rates": {"MXN": 17.15, "EUR": 0.92, "GBP": 0.79},
        "timestamp": "2024-01-15T10:00:00Z",
    }


@app.post("/api/v1/transactions")
def create_transaction(sender: str, receiver: str, amount: float, currency: str = "MXN"):
    """Create a new transaction (mock)."""
    # INTENTIONAL: Uses hardcoded API key for "authentication" (secrets demonstration)
    return {
        "transaction_id": "txn_demo_001",
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "currency": currency,
        "status": "pending",
        "authenticated_with": API_KEY[:10] + "...",
    }
