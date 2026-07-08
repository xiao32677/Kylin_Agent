from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from storage import AUDIT_JSONL_PATH, connect


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def record_audit(
    trace_id: str,
    event_type: str,
    summary: str,
    *,
    session_id: str | None = None,
    user_id: str = "u_admin",
    host_id: str = "host_local",
    risk_level: str | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = {
        "id": new_id("aud"),
        "trace_id": trace_id,
        "session_id": session_id,
        "user_id": user_id,
        "host_id": host_id,
        "event_type": event_type,
        "risk_level": risk_level,
        "summary": summary,
        "detail": detail or {},
        "created_at": now_iso(),
    }
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_events
              (id, trace_id, session_id, user_id, host_id, event_type, risk_level, summary, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["id"],
                trace_id,
                session_id,
                user_id,
                host_id,
                event_type,
                risk_level,
                summary,
                json.dumps(event["detail"], ensure_ascii=False),
                event["created_at"],
            ),
        )

    with AUDIT_JSONL_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event
