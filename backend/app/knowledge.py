from __future__ import annotations

import json
import re
from typing import Any

from audit import new_id, now_iso, record_audit
from storage import connect, rows_to_dicts


LAYERS = {
    "linux_docs": "Linux 知识库",
    "incident_history": "历史故障库",
    "ops_policy": "运维规范库",
    "qa_memory": "用户问答库",
}

KEYWORDS = [
    "oom",
    "oom killer",
    "journalctl",
    "systemctl",
    "systemd",
    "nginx",
    "mysql",
    "mariadb",
    "ssh",
    "sshd",
    "docker",
    "cpu",
    "memory",
    "load",
    "port",
    "listen",
    "lsof",
    "logrotate",
    "磁盘",
    "空间",
    "大文件",
    "删除",
    "端口",
    "占用",
    "释放",
    "日志",
    "错误",
    "失败",
    "异常",
    "服务",
    "重启",
    "审批",
    "权限",
    "注入",
    "僵尸",
    "进程",
    "内存",
    "负载",
]


SEED_ITEMS = [
    {
        "layer": "linux_docs",
        "title": "journalctl 出现 OOM Killer",
        "content": "OOM Killer 表示内核因内存压力终止进程。排查时先查看 journalctl -k 或 dmesg 中的 Killed process 记录，再结合 Top 进程、内存使用率和最近业务变更定位原因。",
        "tags": ["journalctl", "oom", "memory", "kernel"],
        "source_type": "linux_builtin",
        "source_ref": "seed:linux:oom",
        "confidence": 0.92,
    },
    {
        "layer": "linux_docs",
        "title": "端口占用排查",
        "content": "监听端口需要确认 IP、端口、PID、进程名和用户。释放端口前必须重新校验 PID 是否变化，避免误杀新的业务进程。",
        "tags": ["port", "listen", "pid", "process"],
        "source_type": "linux_builtin",
        "source_ref": "seed:linux:port",
        "confidence": 0.9,
    },
    {
        "layer": "linux_docs",
        "title": "已删除但仍被进程占用的文件",
        "content": "Linux 中文件被删除后，如果仍被进程打开，磁盘空间不会立即释放。可用 lsof +L1 定位，通常需要审批后 reload 或 restart 持有文件的服务。",
        "tags": ["lsof", "deleted", "disk", "space"],
        "source_type": "linux_builtin",
        "source_ref": "seed:linux:deleted_open_file",
        "confidence": 0.9,
    },
    {
        "layer": "ops_policy",
        "title": "危险变更必须审批",
        "content": "删除文件、释放端口、停止进程、重启服务、修改权限、写入系统目录都属于中高风险操作。Agent 只能先诊断和生成审批，审批通过后按最小权限执行。",
        "tags": ["approval", "least_privilege", "delete", "restart", "kill"],
        "source_type": "company_policy",
        "source_ref": "seed:policy:approval",
        "confidence": 0.95,
    },
    {
        "layer": "ops_policy",
        "title": "提示词注入处理规范",
        "content": "包含忽略规则、绕过审计、直接执行危险命令等内容时，应优先进入安全护栏。被拦截的请求不发送给外部模型，也不执行 Tool。",
        "tags": ["prompt_injection", "audit", "guardrail"],
        "source_type": "company_policy",
        "source_ref": "seed:policy:injection",
        "confidence": 0.95,
    },
    {
        "layer": "incident_history",
        "title": "历史故障模板：nginx 服务异常",
        "content": "nginx 异常通常先看 systemctl status nginx.service，再看 journalctl -u nginx.service。常见原因包括配置语法错误、端口冲突、证书路径错误和权限不足。",
        "tags": ["nginx", "systemctl", "journalctl", "service"],
        "source_type": "incident_template",
        "source_ref": "seed:incident:nginx",
        "confidence": 0.82,
    },
]


def ensure_knowledge_seed() -> None:
    now = now_iso()
    with connect() as conn:
        for item in SEED_ITEMS:
            conn.execute(
                """
                INSERT OR IGNORE INTO knowledge_items
                  (id, layer, title, content, tags, source_type, source_ref, confidence, created_at, updated_at, use_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    new_id("kb"),
                    item["layer"],
                    item["title"],
                    item["content"],
                    json.dumps(item["tags"], ensure_ascii=False),
                    item["source_type"],
                    item["source_ref"],
                    item["confidence"],
                    now,
                    now,
                ),
            )


def _tokens(text: str) -> set[str]:
    lower = text.lower()
    tokens = set(re.findall(r"[a-z0-9_.@:-]{2,}", lower))
    tokens.update(re.findall(r"\b\d{2,5}\b", lower))
    for keyword in KEYWORDS:
        if keyword.lower() in lower:
            tokens.add(keyword.lower())
    return tokens


def _score(query_tokens: set[str], item: dict[str, Any]) -> float:
    if not query_tokens:
        return 0
    haystack = " ".join(
        [
            str(item.get("title") or ""),
            str(item.get("content") or ""),
            " ".join(item.get("tags") or []),
            str(item.get("layer") or ""),
        ]
    ).lower()
    score = 0.0
    for token in query_tokens:
        if token in haystack:
            score += 3.0 if token in str(item.get("title", "")).lower() else 1.0
    if item.get("layer") == "incident_history":
        score += 0.4
    if item.get("layer") == "ops_policy":
        score += 0.3
    score += min(float(item.get("use_count") or 0), 8) * 0.05
    score += float(item.get("confidence") or 0) * 0.2
    return round(score, 3)


def _normalize_row(item: dict[str, Any]) -> dict[str, Any]:
    tags = item.get("tags")
    if isinstance(tags, str) and tags:
        try:
            item["tags"] = json.loads(tags)
        except json.JSONDecodeError:
            item["tags"] = [tags]
    elif not tags:
        item["tags"] = []
    item["layer_name"] = LAYERS.get(item.get("layer"), item.get("layer"))
    return item


def retrieve_knowledge(query: str, *, limit: int = 5, layer: str | None = None, trace_id: str | None = None, session_id: str | None = None) -> list[dict[str, Any]]:
    ensure_knowledge_seed()
    query_tokens = _tokens(query)
    with connect() as conn:
        if layer and layer in LAYERS:
            rows = conn.execute("SELECT * FROM knowledge_items WHERE layer = ? ORDER BY updated_at DESC LIMIT 300", (layer,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM knowledge_items ORDER BY updated_at DESC LIMIT 300").fetchall()
    ranked = []
    for row in rows_to_dicts(rows):
        item = _normalize_row(row)
        score = _score(query_tokens, item)
        if score > 0:
            item["score"] = score
            ranked.append(item)
    ranked.sort(key=lambda item: item["score"], reverse=True)
    refs = ranked[:limit]
    if refs:
        with connect() as conn:
            conn.executemany(
                "UPDATE knowledge_items SET use_count = use_count + 1, updated_at = ? WHERE id = ?",
                [(now_iso(), item["id"]) for item in refs],
            )
        if trace_id:
            record_audit(
                trace_id,
                "knowledge_retrieved",
                "RAG 已检索多层知识库",
                session_id=session_id,
                detail={"query": query, "refs": [{"id": item["id"], "layer": item["layer"], "title": item["title"], "score": item["score"]} for item in refs]},
            )
    return refs


def add_knowledge_item(
    *,
    layer: str,
    title: str,
    content: str,
    tags: list[str] | None = None,
    source_type: str = "manual",
    source_ref: str = "",
    confidence: float = 0.75,
) -> dict[str, Any]:
    if layer not in LAYERS:
        return {"success": False, "error": {"code": "KB_LAYER_INVALID", "message": "知识库层级无效"}}
    title = title.strip()[:160]
    content = content.strip()[:4000]
    if not title or not content:
        return {"success": False, "error": {"code": "REQ_SCHEMA_INVALID", "message": "title/content 不能为空"}}
    now = now_iso()
    item_id = new_id("kb")
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO knowledge_items
              (id, layer, title, content, tags, source_type, source_ref, confidence, created_at, updated_at, use_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                item_id,
                layer,
                title,
                content,
                json.dumps(tags or [], ensure_ascii=False),
                source_type,
                source_ref,
                max(0.0, min(float(confidence), 1.0)),
                now,
                now,
            ),
        )
    return {"success": True, "item": get_knowledge_item(item_id)}


def get_knowledge_item(item_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM knowledge_items WHERE id = ?", (item_id,)).fetchone()
    return _normalize_row(dict(row)) if row else None


def list_knowledge_items(layer: str | None = None, query: str | None = None, limit: int = 80) -> dict[str, Any]:
    ensure_knowledge_seed()
    if query:
        return {"items": retrieve_knowledge(query, limit=limit, layer=layer)}
    params: list[Any] = []
    where = ""
    if layer and layer in LAYERS:
        where = "WHERE layer = ?"
        params.append(layer)
    params.append(limit)
    with connect() as conn:
        rows = conn.execute(f"SELECT * FROM knowledge_items {where} ORDER BY updated_at DESC LIMIT ?", tuple(params)).fetchall()
    return {"items": [_normalize_row(item) for item in rows_to_dicts(rows)]}


def knowledge_stats() -> dict[str, Any]:
    ensure_knowledge_seed()
    with connect() as conn:
        rows = conn.execute("SELECT layer, COUNT(*) AS count FROM knowledge_items GROUP BY layer").fetchall()
        total = conn.execute("SELECT COUNT(*) AS count FROM knowledge_items").fetchone()["count"]
        today_added = conn.execute("SELECT COUNT(*) AS count FROM knowledge_items WHERE date(created_at) = date('now', 'localtime')").fetchone()["count"]
        manual_total = conn.execute("SELECT COUNT(*) AS count FROM knowledge_items WHERE source_type = 'manual'").fetchone()["count"]
        learned_total = conn.execute("SELECT COUNT(*) AS count FROM knowledge_items WHERE source_type IN ('chat_trace', 'approval_trace')").fetchone()["count"]
        total_use_count = conn.execute("SELECT COALESCE(SUM(use_count), 0) AS count FROM knowledge_items").fetchone()["count"]
        avg_confidence = conn.execute("SELECT COALESCE(AVG(confidence), 0) AS value FROM knowledge_items").fetchone()["value"]
        recent = conn.execute("SELECT * FROM knowledge_items ORDER BY updated_at DESC LIMIT 6").fetchall()
    counts = {layer: 0 for layer in LAYERS}
    for row in rows:
        counts[row["layer"]] = row["count"]
    return {
        "total": total,
        "today_added": today_added,
        "manual_total": manual_total,
        "learned_total": learned_total,
        "total_use_count": total_use_count,
        "avg_confidence": round(float(avg_confidence or 0) * 100, 1),
        "layers": [{"key": key, "name": name, "count": counts.get(key, 0)} for key, name in LAYERS.items()],
        "recent": [_normalize_row(item) for item in rows_to_dicts(recent)],
    }


def learn_from_chat(
    *,
    trace_id: str,
    session_id: str,
    user_text: str,
    answer: str,
    intent: dict[str, Any],
    tool_results: list[dict[str, Any]],
    issues: list[dict[str, Any]],
    approval: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    learned: list[dict[str, Any]] = []
    category = intent.get("category") or "unknown"
    if category in {"clarification"}:
        return learned

    tool_names = [result.get("tool") for result in tool_results if result.get("tool")]
    qa_content = "\n".join(
        [
            f"用户问题：{user_text}",
            f"识别意图：{category}",
            f"调用工具：{', '.join(tool_names) or '无'}",
            f"回答结论：{answer[:900]}",
        ]
    )
    qa = add_knowledge_item(
        layer="qa_memory",
        title=f"问答沉淀：{user_text[:48]}",
        content=qa_content,
        tags=list({category, *tool_names}),
        source_type="chat_trace",
        source_ref=trace_id,
        confidence=0.78,
    )
    if qa.get("success"):
        learned.append(qa["item"])

    if issues:
        issue = issues[0]
        evidence = "；".join(str(item) for item in issue.get("evidence", [])[:5])
        content = "\n".join(
            [
                f"故障现象：{user_text}",
                f"问题位置：{issue.get('where') or '-'}",
                f"定位结论：{issue.get('title')}",
                f"证据：{evidence or '见 trace 审计'}",
                f"建议：{issue.get('suggestion') or answer[:300]}",
            ]
        )
        incident = add_knowledge_item(
            layer="incident_history",
            title=f"历史故障：{issue.get('title')}",
            content=content,
            tags=list({category, issue.get("severity", "unknown"), *tool_names}),
            source_type="chat_trace",
            source_ref=trace_id,
            confidence=0.86,
        )
        if incident.get("success"):
            learned.append(incident["item"])

    if approval:
        policy = add_knowledge_item(
            layer="ops_policy",
            title=f"审批案例：{approval.get('command_preview')}",
            content=f"用户请求：{user_text}\n风险等级：{approval.get('risk_level')}\n审批动作：{approval.get('action')}\n影响：{approval.get('impact')}\n回滚：{approval.get('rollback_plan')}",
            tags=["approval", approval.get("risk_level", "medium"), category],
            source_type="approval_trace",
            source_ref=trace_id,
            confidence=0.8,
        )
        if policy.get("success"):
            learned.append(policy["item"])

    if learned:
        record_audit(
            trace_id,
            "knowledge_learned",
            "Agent 已从本次问答沉淀知识",
            session_id=session_id,
            risk_level=intent.get("risk_level"),
            detail={"items": [{"id": item["id"], "layer": item["layer"], "title": item["title"]} for item in learned]},
        )
    return learned
