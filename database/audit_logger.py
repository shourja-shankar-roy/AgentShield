
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "database" / "agentshield_audit.db"


def initialize_database():
    """Create or safely upgrade the audit log table."""

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_role TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                identity_id TEXT,
                user_id TEXT
            )
        """)

        # Upgrade existing databases without deleting old records.
        existing_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(audit_logs)"
            ).fetchall()
        }

        if "identity_id" not in existing_columns:
            connection.execute(
                "ALTER TABLE audit_logs ADD COLUMN identity_id TEXT"
            )

        if "user_id" not in existing_columns:
            connection.execute(
                "ALTER TABLE audit_logs ADD COLUMN user_id TEXT"
            )


def log_event(
    user_role,
    tool_name,
    decision,
    status,
    details="",
    identity_id=None,
    user_id=None,
):
    """Record a security or tool-execution event."""

    initialize_database()

    timestamp = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute("""
            INSERT INTO audit_logs (
                timestamp,
                user_role,
                tool_name,
                decision,
                status,
                details,
                identity_id,
                user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            str(user_role),
            str(tool_name),
            str(decision),
            str(status),
            str(details),
            str(identity_id) if identity_id is not None else None,
            str(user_id) if user_id is not None else None,
        ))


def log_input_inspection(
    identity_context,
    decision,
    risk_level,
    categories,
    findings,
):
    """
    Persist an input-inspection decision.

    The original user prompt is deliberately not stored.
    """

    if decision not in {"ALLOWED", "FLAGGED", "BLOCKED"}:
        raise ValueError("Invalid input-inspection decision.")

    if risk_level not in {"LOW", "MEDIUM", "HIGH"}:
        raise ValueError("Invalid input-inspection risk level.")

    details = {
        "risk_level": risk_level,
        "categories": categories,
        "findings": findings,
    }

    if decision == "BLOCKED":
        status = "BLOCKED"
    elif decision == "FLAGGED":
        status = "FLAGGED"
    else:
        status = "SUCCESS"

    log_event(
        user_role=identity_context.role,
        tool_name="input_inspector",
        decision=decision,
        status=status,
        details=json.dumps(details),
        identity_id=identity_context.identity_id,
        user_id=identity_context.user_id,
    )


def get_recent_logs(limit=50):
    """Retrieve the most recent audit events."""

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("Limit must be a positive integer.")

    initialize_database()

    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT
                id,
                timestamp,
                user_role,
                identity_id,
                user_id,
                tool_name,
                decision,
                status,
                details
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


if __name__ == "__main__":

    print("\nAgentShield Audit Logger Test")
    print("=" * 40)

    initialize_database()
    print("\n1. Database initialized.")

    log_event(
        user_role="employee",
        tool_name="search_policy",
        decision="ALLOWED",
        status="SUCCESS",
        details="Test policy search event.",
        identity_id="alice",
        user_id="EMP001",
    )

    log_event(
        user_role="guest",
        tool_name="get_employee_record",
        decision="DENIED",
        status="BLOCKED",
        details="Test unauthorized access event.",
        identity_id="guest",
    )

    print("\n2. Test events recorded.")

    print("\n3. Recent audit logs:")

    logs = get_recent_logs(limit=10)
    print(json.dumps(logs, indent=4))

    print("\n4. Total test events retrieved:", len(logs))
