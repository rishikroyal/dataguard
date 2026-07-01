"""
Audit Logger
Records all system events to SQLite for compliance tracking.
Provides a complete audit trail for regulatory requirements.
"""

import sqlite3
import json
import logging
import uuid
import os
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("AUDIT_DB_PATH", "./audit_logs/audit.db")


class AuditLogger:
    """
    Enterprise-grade audit logging using SQLite.
    Records: document uploads, scans, Q&A sessions, exports, user actions.
    """

    EVENT_TYPES = {
        "DOCUMENT_UPLOAD":    "Document uploaded for analysis",
        "SCAN_COMPLETE":      "Sensitive data scan completed",
        "QA_QUERY":           "User asked a question about document",
        "REPORT_GENERATED":   "Compliance report generated",
        "REDACTION_APPLIED":  "Document redaction applied",
        "EXPORT_CSV":         "Detection results exported as CSV",
        "EXPORT_PDF":         "Compliance report exported as PDF",
        "API_KEY_CONFIGURED": "Groq API key configured",
        "SESSION_START":      "Analysis session started",
        "ERROR":              "System error occurred",
    }

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH
        self._ensure_directory()
        self._init_db()

    def _ensure_directory(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create audit tables if they don't exist."""
        try:
            with self._get_conn() as conn:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS audit_events (
                        id          TEXT PRIMARY KEY,
                        timestamp   TEXT NOT NULL,
                        session_id  TEXT NOT NULL,
                        event_type  TEXT NOT NULL,
                        filename    TEXT,
                        user_action TEXT,
                        details     TEXT,
                        risk_level  TEXT,
                        detection_count INTEGER DEFAULT 0,
                        duration_ms INTEGER,
                        ip_address  TEXT DEFAULT 'localhost',
                        status      TEXT DEFAULT 'SUCCESS'
                    );

                    CREATE INDEX IF NOT EXISTS idx_session ON audit_events(session_id);
                    CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type);
                """)
        except Exception as e:
            logger.error(f"Failed to initialize audit DB: {e}")

    def log(
        self,
        event_type: str,
        session_id: str,
        filename: Optional[str] = None,
        user_action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        risk_level: Optional[str] = None,
        detection_count: int = 0,
        duration_ms: Optional[int] = None,
        status: str = "SUCCESS",
    ) -> str:
        """Log an audit event. Returns the event ID."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO audit_events
                       (id, timestamp, session_id, event_type, filename, user_action,
                        details, risk_level, detection_count, duration_ms, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event_id,
                        timestamp,
                        session_id,
                        event_type,
                        filename,
                        user_action,
                        json.dumps(details) if details else None,
                        risk_level,
                        detection_count,
                        duration_ms,
                        status,
                    ),
                )
        except Exception as e:
            logger.error(f"Audit log failed: {e}")

        return event_id

    def get_recent_events(self, limit: int = 100, session_id: Optional[str] = None) -> List[Dict]:
        """Retrieve recent audit events."""
        try:
            with self._get_conn() as conn:
                if session_id:
                    rows = conn.execute(
                        "SELECT * FROM audit_events WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
                        (session_id, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?",
                        (limit,),
                    ).fetchall()

                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to retrieve audit events: {e}")
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregate statistics from audit log."""
        try:
            with self._get_conn() as conn:
                total = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
                by_type = conn.execute(
                    "SELECT event_type, COUNT(*) as cnt FROM audit_events GROUP BY event_type"
                ).fetchall()
                by_risk = conn.execute(
                    "SELECT risk_level, COUNT(*) as cnt FROM audit_events WHERE risk_level IS NOT NULL GROUP BY risk_level"
                ).fetchall()
                recent_sessions = conn.execute(
                    "SELECT DISTINCT session_id, MIN(timestamp) as started FROM audit_events GROUP BY session_id ORDER BY started DESC LIMIT 10"
                ).fetchall()

                return {
                    "total_events": total,
                    "by_event_type": {row[0]: row[1] for row in by_type},
                    "by_risk_level": {row[0]: row[1] for row in by_risk},
                    "recent_sessions": [dict(row) for row in recent_sessions],
                }
        except Exception as e:
            logger.error(f"Stats query failed: {e}")
            return {"total_events": 0, "by_event_type": {}, "by_risk_level": {}, "recent_sessions": []}

    def export_to_csv(self) -> str:
        """Export audit log to CSV string."""
        import csv
        import io

        events = self.get_recent_events(limit=10000)
        if not events:
            return "No audit events found."

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=events[0].keys())
        writer.writeheader()
        writer.writerows(events)
        return output.getvalue()
