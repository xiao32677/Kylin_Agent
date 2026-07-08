from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "a2_agent.sqlite3"
AUDIT_JSONL_PATH = DATA_DIR / "audit_events.jsonl"


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def connect() -> sqlite3.Connection:
    ensure_data_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    ensure_data_dir()
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
              id TEXT PRIMARY KEY,
              title TEXT,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
              id TEXT PRIMARY KEY,
              session_id TEXT NOT NULL,
              trace_id TEXT NOT NULL,
              role TEXT NOT NULL,
              content TEXT NOT NULL,
              metadata TEXT,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
              id TEXT PRIMARY KEY,
              trace_id TEXT NOT NULL,
              session_id TEXT,
              user_id TEXT,
              host_id TEXT,
              event_type TEXT NOT NULL,
              risk_level TEXT,
              summary TEXT NOT NULL,
              detail TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_trace
              ON audit_events(trace_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_audit_risk
              ON audit_events(risk_level, created_at);

            CREATE TABLE IF NOT EXISTS tool_calls (
              id TEXT PRIMARY KEY,
              trace_id TEXT NOT NULL,
              tool_name TEXT NOT NULL,
              arguments TEXT NOT NULL,
              risk_level TEXT NOT NULL,
              status TEXT NOT NULL,
              error_code TEXT,
              output_summary TEXT,
              duration_ms INTEGER,
              executed_by TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tool_trace
              ON tool_calls(trace_id, created_at);

            CREATE TABLE IF NOT EXISTS security_checks (
              id TEXT PRIMARY KEY,
              trace_id TEXT NOT NULL,
              input_type TEXT NOT NULL,
              input_text TEXT NOT NULL,
              risk_level TEXT NOT NULL,
              allowed INTEGER NOT NULL,
              action TEXT NOT NULL,
              matched_rules TEXT,
              error_code TEXT,
              created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_security_trace
              ON security_checks(trace_id, created_at);

            CREATE TABLE IF NOT EXISTS approvals (
              id TEXT PRIMARY KEY,
              trace_id TEXT NOT NULL,
              requester_id TEXT NOT NULL,
              approver_id TEXT,
              status TEXT NOT NULL,
              risk_level TEXT NOT NULL,
              action TEXT NOT NULL,
              command_preview TEXT,
              impact TEXT,
              rollback_plan TEXT,
              payload_hash TEXT NOT NULL,
              comment TEXT,
              expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL,
              decided_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_approval_trace
              ON approvals(trace_id, created_at);

            CREATE TABLE IF NOT EXISTS approval_payloads (
              approval_id TEXT PRIMARY KEY,
              trace_id TEXT NOT NULL,
              tool_name TEXT NOT NULL,
              arguments TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS app_users (
              id TEXT PRIMARY KEY,
              username TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'active',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_tokens (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tool_states (
              name TEXT PRIMARY KEY,
              enabled INTEGER NOT NULL DEFAULT 1,
              updated_at TEXT NOT NULL,
              updated_by TEXT
            );

            CREATE TABLE IF NOT EXISTS knowledge_items (
              id TEXT PRIMARY KEY,
              layer TEXT NOT NULL,
              title TEXT NOT NULL,
              content TEXT NOT NULL,
              tags TEXT,
              source_type TEXT NOT NULL,
              source_ref TEXT,
              confidence REAL NOT NULL DEFAULT 0.75,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              use_count INTEGER NOT NULL DEFAULT 0,
              UNIQUE(layer, source_ref, title)
            );

            CREATE INDEX IF NOT EXISTS idx_knowledge_layer
              ON knowledge_items(layer, updated_at);
            """
        )


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        for key in ("detail", "metadata", "arguments", "matched_rules"):
            if key in item and isinstance(item[key], str) and item[key]:
                try:
                    item[key] = json.loads(item[key])
                except json.JSONDecodeError:
                    pass
        result.append(item)
    return result
