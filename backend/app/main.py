from __future__ import annotations

import json
import mimetypes
import os
import sys
import csv
from io import StringIO
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from auth import authenticate, ensure_default_admin, login, logout_token, require_role
from agent import decide_approval_safe, get_approvals, get_audit, get_audit_trace, get_dashboard, get_knowledge, get_knowledge_stats, get_model_status, get_stats, get_tools, handle_chat, invoke_registered_tool
from guardrail import check_text
from knowledge import add_knowledge_item, ensure_knowledge_seed
from storage import ROOT_DIR, init_db
from tools import get_tool_health, set_tool_enabled


FRONTEND_DIR = ROOT_DIR / "frontend"


class A2Handler(BaseHTTPRequestHandler):
    server_version = "A2SecOpsAgent/0.1"

    def log_message(self, fmt: str, *args: object) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw or "{}")

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, body_text: str, content_type: str = "text/plain; charset=utf-8", status: int = 200) -> None:
        body = body_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if path.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        elif path.suffix in {".html", ".css"}:
            content_type += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _user(self) -> dict | None:
        return authenticate(self.headers.get("Authorization"))

    def _require(self, allowed_roles: set[str]) -> dict | None:
        user = self._user()
        ok, error = require_role(user, allowed_roles)
        if not ok:
            status = 401 if error and error["error"]["code"] == "AUTH_UNAUTHORIZED" else 403
            self._send_json(error or {"error": {"code": "AUTH_FORBIDDEN", "message": "无权访问"}}, status)
            return None
        return user

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/api/v1/health":
            self._send_json({"status": "ok", "service": "a2-secops-agent"})
        elif path == "/api/v1/auth/me":
            user = self._require({"admin", "operator", "auditor"})
            if user:
                self._send_json({"user": user})
        elif path == "/api/v1/dashboard":
            if self._require({"admin", "operator", "auditor"}):
                self._send_json(get_dashboard())
        elif path == "/api/v1/stats":
            if self._require({"admin", "operator", "auditor"}):
                self._send_json(get_stats())
        elif path == "/api/v1/tools":
            if self._require({"admin", "operator", "auditor"}):
                self._send_json(get_tools())
        elif path == "/api/v1/tools/health":
            if self._require({"admin", "operator", "auditor"}):
                self._send_json(get_tool_health(query.get("name", [None])[0]))
        elif path == "/api/v1/llm/status":
            if self._require({"admin", "operator", "auditor"}):
                self._send_json(get_model_status())
        elif path == "/api/v1/knowledge":
            if self._require({"admin", "operator", "auditor"}):
                self._send_json(
                    get_knowledge(
                        layer=query.get("layer", [None])[0],
                        query=query.get("q", [None])[0],
                        limit=int(query.get("limit", ["80"])[0]),
                    )
                )
        elif path == "/api/v1/knowledge/stats":
            if self._require({"admin", "operator", "auditor"}):
                self._send_json(get_knowledge_stats())
        elif path == "/api/v1/audit":
            if self._require({"admin", "auditor"}):
                trace_id = query.get("trace_id", [None])[0]
                limit = int(query.get("limit", ["80"])[0])
                result = get_audit(
                    limit=limit,
                    trace_id=trace_id,
                    user_id=query.get("user_id", [None])[0],
                    risk_level=query.get("risk_level", [None])[0],
                    event_type=query.get("event_type", [None])[0],
                    tool_name=query.get("tool_name", [None])[0],
                    date_from=query.get("from", [None])[0],
                    date_to=query.get("to", [None])[0],
                )
                fmt = (query.get("format", ["json"])[0] or "json").lower()
                if fmt == "jsonl":
                    self._send_text("\n".join(json.dumps(item, ensure_ascii=False) for item in result["items"]), "application/x-ndjson; charset=utf-8")
                elif fmt == "csv":
                    buf = StringIO()
                    writer = csv.DictWriter(buf, fieldnames=["id", "trace_id", "session_id", "user_id", "host_id", "event_type", "risk_level", "summary", "created_at"])
                    writer.writeheader()
                    for item in result["items"]:
                        writer.writerow({key: item.get(key) for key in writer.fieldnames})
                    self._send_text(buf.getvalue(), "text/csv; charset=utf-8")
                else:
                    self._send_json(result)
        elif path.startswith("/api/v1/audit/trace/"):
            if self._require({"admin", "auditor"}):
                trace_id = path.rsplit("/", 1)[-1]
                self._send_json(get_audit_trace(trace_id))
        elif path == "/api/v1/approvals":
            if self._require({"admin"}):
                self._send_json(get_approvals())
        elif path == "/" or path == "/index.html":
            self._send_file(FRONTEND_DIR / "index.html")
        else:
            candidate = (FRONTEND_DIR / path.lstrip("/")).resolve()
            if FRONTEND_DIR.resolve() in candidate.parents or candidate == FRONTEND_DIR.resolve():
                self._send_file(candidate)
            else:
                self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            payload = self._read_json()
            if path == "/api/v1/auth/login":
                result = login(str(payload.get("username", "")), str(payload.get("password", "")))
                self._send_json(result, 200 if result.get("success") else 401)
            elif path == "/api/v1/auth/logout":
                self._send_json(logout_token(self.headers.get("Authorization")))
            elif path == "/api/v1/chat":
                user = self._require({"admin", "operator"})
                if not user:
                    return
                content = str(payload.get("content", "")).strip()
                if not content:
                    self._send_json({"error": {"code": "REQ_SCHEMA_INVALID", "message": "content 不能为空"}}, 400)
                    return
                self._send_json(handle_chat(content, payload.get("session_id"), user_id=user["id"]))
            elif path == "/api/v1/security/check-command":
                if not self._require({"admin", "operator"}):
                    return
                text = str(payload.get("command") or payload.get("text") or "")
                self._send_json(check_text(text, input_type="command"))
            elif path == "/api/v1/knowledge":
                user = self._require({"admin", "operator"})
                if not user:
                    return
                result = add_knowledge_item(
                    layer=str(payload.get("layer") or ""),
                    title=str(payload.get("title") or ""),
                    content=str(payload.get("content") or ""),
                    tags=payload.get("tags") if isinstance(payload.get("tags"), list) else [],
                    source_type="manual",
                    source_ref=f"manual:{user['id']}",
                    confidence=float(payload.get("confidence") or 0.75),
                )
                self._send_json(result, 200 if result.get("success") else 400)
            elif path.startswith("/api/v1/tools/") and path.endswith("/invoke"):
                if not self._require({"admin", "operator"}):
                    return
                parts = path.strip("/").split("/")
                tool_name = parts[3]
                self._send_json(invoke_registered_tool(tool_name, payload.get("arguments") or {}, payload.get("trace_id")))
            elif path.startswith("/api/v1/tools/") and (path.endswith("/enable") or path.endswith("/disable")):
                user = self._require({"admin"})
                if not user:
                    return
                parts = path.strip("/").split("/")
                tool_name = parts[3]
                enabled = path.endswith("/enable")
                self._send_json(set_tool_enabled(tool_name, enabled, updated_by=user["id"]))
            elif path.startswith("/api/v1/approvals/") and (path.endswith("/approve") or path.endswith("/reject")):
                user = self._require({"admin"})
                if not user:
                    return
                parts = path.strip("/").split("/")
                approval_id = parts[3]
                approved = path.endswith("/approve")
                self._send_json(decide_approval_safe(approval_id, approved, str(payload.get("comment", "")), approver_id=user["id"]))
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
        except json.JSONDecodeError:
            self._send_json({"error": {"code": "REQ_INVALID_JSON", "message": "请求 JSON 无效"}}, 400)
        except Exception as exc:
            self._send_json({"error": {"code": "INTERNAL_ERROR", "message": str(exc)}}, 500)


def main() -> None:
    init_db()
    ensure_default_admin()
    ensure_knowledge_seed()
    host = os.environ.get("A2_HOST", "0.0.0.0")
    port = int(os.environ.get("A2_PORT", "8765"))
    httpd = ThreadingHTTPServer((host, port), A2Handler)
    print(f"A2 SecOps Agent listening on http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
