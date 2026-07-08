from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from audit import new_id, now_iso
from storage import connect, rows_to_dicts


DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "a2admin123"
DEFAULT_OPERATOR_USER = "operator"
DEFAULT_OPERATOR_PASSWORD = "a2operator123"
DEFAULT_AUDITOR_USER = "auditor"
DEFAULT_AUDITOR_PASSWORD = "a2auditor123"
TOKEN_TTL_HOURS = 12
ROLES = {"admin", "operator", "auditor"}
LOGIN_FAIL_WINDOW_SECONDS = int(os.environ.get("A2_LOGIN_FAIL_WINDOW_SECONDS", "300"))
LOGIN_LOCK_SECONDS = int(os.environ.get("A2_LOGIN_LOCK_SECONDS", "300"))
LOGIN_MAX_FAILURES = int(os.environ.get("A2_LOGIN_MAX_FAILURES", "5"))
_LOGIN_FAILURES: dict[str, list[float]] = {}


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return "pbkdf2_sha256$120000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iterations, salt_b64, digest_b64 = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _ensure_user(username: str, password: str, role: str) -> None:
    created = now_iso()
    with connect() as conn:
        row = conn.execute("SELECT id FROM app_users WHERE username = ?", (username,)).fetchone()
        if row:
            return
        conn.execute(
            """
            INSERT INTO app_users (id, username, password_hash, role, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (new_id("usr"), username, _hash_password(password), role, "active", created, created),
        )


def _login_key(username: str, client_id: str = "") -> str:
    return f"{client_id.strip() or 'local'}:{username.strip().lower()}"


def _rate_limit_error(wait_seconds: int) -> dict[str, Any]:
    return {
        "success": False,
        "error": {
            "code": "AUTH_RATE_LIMITED",
            "message": f"登录失败次数过多，请 {wait_seconds} 秒后再试",
        },
    }


def _check_login_limit(username: str, client_id: str = "") -> dict[str, Any] | None:
    key = _login_key(username, client_id)
    now = time.time()
    attempts = [ts for ts in _LOGIN_FAILURES.get(key, []) if now - ts <= LOGIN_FAIL_WINDOW_SECONDS]
    _LOGIN_FAILURES[key] = attempts
    if len(attempts) >= LOGIN_MAX_FAILURES:
        oldest = min(attempts)
        wait = max(1, int(LOGIN_LOCK_SECONDS - (now - oldest)))
        return _rate_limit_error(wait)
    return None


def _record_login_failure(username: str, client_id: str = "") -> None:
    key = _login_key(username, client_id)
    now = time.time()
    attempts = [ts for ts in _LOGIN_FAILURES.get(key, []) if now - ts <= LOGIN_FAIL_WINDOW_SECONDS]
    attempts.append(now)
    _LOGIN_FAILURES[key] = attempts


def _clear_login_failures(username: str, client_id: str = "") -> None:
    _LOGIN_FAILURES.pop(_login_key(username, client_id), None)


def ensure_default_admin() -> None:
    users = [
        (
            os.environ.get("A2_ADMIN_USER", DEFAULT_ADMIN_USER).strip() or DEFAULT_ADMIN_USER,
            os.environ.get("A2_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD),
            "admin",
        ),
        (
            os.environ.get("A2_OPERATOR_USER", DEFAULT_OPERATOR_USER).strip() or DEFAULT_OPERATOR_USER,
            os.environ.get("A2_OPERATOR_PASSWORD", DEFAULT_OPERATOR_PASSWORD),
            "operator",
        ),
        (
            os.environ.get("A2_AUDITOR_USER", DEFAULT_AUDITOR_USER).strip() or DEFAULT_AUDITOR_USER,
            os.environ.get("A2_AUDITOR_PASSWORD", DEFAULT_AUDITOR_PASSWORD),
            "auditor",
        ),
    ]
    for username, password, role in users:
        _ensure_user(username, password, role)


def login(username: str, password: str) -> dict[str, Any]:
    limited = _check_login_limit(username)
    if limited:
        return limited
    with connect() as conn:
        row = conn.execute("SELECT * FROM app_users WHERE username = ? AND status = 'active'", (username,)).fetchone()
        if not row:
            _record_login_failure(username)
            return {"success": False, "error": {"code": "AUTH_INVALID", "message": "用户名或密码错误"}}
        user = rows_to_dicts([row])[0]
        if not _verify_password(password, user["password_hash"]):
            _record_login_failure(username)
            return {"success": False, "error": {"code": "AUTH_INVALID", "message": "用户名或密码错误"}}
        _clear_login_failures(username)
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.now(timezone.utc).astimezone() + timedelta(hours=TOKEN_TTL_HOURS)).isoformat(timespec="seconds")
        conn.execute(
            "INSERT INTO auth_tokens (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token, user["id"], expires_at, now_iso()),
        )
    return {
        "success": True,
        "token": token,
        "expires_at": expires_at,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
    }


def logout_token(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        return {"success": True, "revoked": False}
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        return {"success": True, "revoked": False}
    with connect() as conn:
        cur = conn.execute("DELETE FROM auth_tokens WHERE token = ?", (token,))
    return {"success": True, "revoked": cur.rowcount > 0}


def change_password(user_id: str, current_password: str, new_password: str) -> dict[str, Any]:
    current_password = str(current_password or "")
    new_password = str(new_password or "")
    if len(new_password) < 8:
        return {"success": False, "error": {"code": "AUTH_PASSWORD_WEAK", "message": "新密码至少需要 8 位"}}
    if current_password == new_password:
        return {"success": False, "error": {"code": "AUTH_PASSWORD_REUSED", "message": "新密码不能与当前密码相同"}}
    with connect() as conn:
        row = conn.execute("SELECT * FROM app_users WHERE id = ? AND status = 'active'", (user_id,)).fetchone()
        if not row:
            return {"success": False, "error": {"code": "AUTH_USER_NOT_FOUND", "message": "用户不存在或已停用"}}
        user = rows_to_dicts([row])[0]
        if not _verify_password(current_password, user["password_hash"]):
            return {"success": False, "error": {"code": "AUTH_INVALID_CURRENT_PASSWORD", "message": "当前密码不正确"}}
        conn.execute(
            "UPDATE app_users SET password_hash = ?, updated_at = ? WHERE id = ?",
            (_hash_password(new_password), now_iso(), user_id),
        )
        conn.execute("DELETE FROM auth_tokens WHERE user_id = ?", (user_id,))
    _clear_login_failures(str(user["username"]))
    return {"success": True, "message": "密码已修改，请重新登录"}


def authenticate(authorization: str | None) -> dict[str, Any] | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.removeprefix("Bearer ").strip()
    now = datetime.now(timezone.utc).astimezone()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, u.role, u.status, t.expires_at
            FROM auth_tokens t
            JOIN app_users u ON u.id = t.user_id
            WHERE t.token = ?
            """,
            (token,),
        ).fetchone()
    if not row:
        return None
    user = rows_to_dicts([row])[0]
    try:
        expires_at = datetime.fromisoformat(user["expires_at"])
    except ValueError:
        return None
    if user["status"] != "active" or expires_at < now:
        return None
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


def require_role(user: dict[str, Any] | None, allowed_roles: set[str]) -> tuple[bool, dict[str, Any] | None]:
    if not user:
        return False, {"error": {"code": "AUTH_UNAUTHORIZED", "message": "请先登录"}}
    if user["role"] not in allowed_roles:
        return False, {"error": {"code": "AUTH_FORBIDDEN", "message": "当前角色无权执行该操作"}}
    return True, None
