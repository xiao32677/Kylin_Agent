from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from audit import new_id, now_iso, record_audit
from guardrail import check_text, classify_intent, payload_hash
from knowledge import learn_from_chat, list_knowledge_items, knowledge_stats, retrieve_knowledge
from llm_adapter import get_llm_status, plan_with_deepseek, summarize_with_deepseek
from storage import AUDIT_JSONL_PATH, DB_PATH, connect, rows_to_dicts
from tools import TOOLS, get_tool_health, invoke_tool, list_tool_metadata, set_tool_enabled


def _desktop_root() -> Path:
    configured = os.environ.get("A2_DESKTOP_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()

    owner = os.environ.get("A2_DESKTOP_OWNER", "xiao").strip() or "xiao"
    for candidate in (Path("/home") / owner / "桌面", Path("/home") / owner / "Desktop"):
        if candidate.exists():
            return candidate
    return Path.home() / "Desktop"


def _save_message(session_id: str, trace_id: str, role: str, content: str, metadata: dict[str, Any] | None = None) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO messages (id, session_id, trace_id, role, content, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (new_id("msg"), session_id, trace_id, role, content, json.dumps(metadata or {}, ensure_ascii=False), now_iso()),
        )


def ensure_session(session_id: str | None, title: str = "安全运维会话") -> str:
    if session_id:
        return session_id
    created = now_iso()
    sid = new_id("sess")
    with connect() as conn:
        conn.execute(
            "INSERT INTO sessions (id, title, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (sid, title, "active", created, created),
        )
    return sid


def _recent_context(session_id: str, limit: int = 6) -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT role, content, metadata, created_at
            FROM messages
            WHERE session_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (session_id, limit),
        ).fetchall()
    return list(reversed(rows_to_dicts(rows)))


def _record_security_check(trace_id: str, text: str, result: dict[str, Any]) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO security_checks
              (id, trace_id, input_type, input_text, risk_level, allowed, action, matched_rules, error_code, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("sec"),
                trace_id,
                result["input_type"],
                text,
                result["risk_level"],
                1 if result["allowed"] else 0,
                result["action"],
                json.dumps(result["matched_rules"], ensure_ascii=False),
                result["error_code"],
                now_iso(),
            ),
        )


def _record_tool_call(trace_id: str, tool_result: dict[str, Any], arguments: dict[str, Any]) -> None:
    output_summary = json.dumps(tool_result.get("data"), ensure_ascii=False)[:500] if tool_result.get("data") is not None else ""
    error = tool_result.get("error") or {}
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO tool_calls
              (id, trace_id, tool_name, arguments, risk_level, status, error_code, output_summary, duration_ms, executed_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id("tc"),
                trace_id,
                tool_result["tool"],
                json.dumps(arguments, ensure_ascii=False),
                tool_result["risk_level"],
                "succeeded" if tool_result["success"] else "failed",
                error.get("code"),
                output_summary,
                tool_result["duration_ms"],
                tool_result["executed_by"],
                now_iso(),
            ),
        )


def _extract_port(text: str) -> int | None:
    match = re.search(r"\b([1-9][0-9]{1,4})\b", text)
    if not match:
        return None
    port = int(match.group(1))
    return port if 1 <= port <= 65535 else None


def _extract_service(text: str) -> str:
    lower = text.lower()
    known = ["a2-secops-agent", "sshd", "ssh", "nginx", "mysql", "mariadb", "docker"]
    for name in known:
        if name in lower:
            return f"{name}.service" if "." not in name else name
    match = re.search(r"\b([A-Za-z0-9_.@:-]+\.service)\b", text)
    if match:
        return match.group(1)
    return "a2-secops-agent.service"


def _arguments_for_tool(tool: str, text: str) -> dict[str, Any]:
    if tool == "list_ports":
        port = _extract_port(text)
        return {"port": port} if port else {}
    if tool == "get_service_status":
        return {"service": _extract_service(text)}
    if tool == "find_large_files":
        return {"min_size_mb": 20, "limit": 12, "max_depth": 4}
    if tool == "find_deleted_open_files":
        return {"limit": 20}
    if tool == "query_journal":
        if any(name in text.lower() for name in ("nginx", "mysql", "mariadb", "ssh", "sshd", "docker", "a2-secops-agent")):
            return {"lines": 80, "unit": _extract_service(text)}
        return {"lines": 60}
    if tool == "query_kernel_log":
        return {"lines": 60}
    if tool == "list_processes":
        return {"limit": 20}
    if tool == "sample_top_processes":
        return {"limit": 8, "interval": 0.2}
    return {}


def _needs_clarification(text: str, intent: dict[str, Any]) -> str | None:
    if intent.get("category") not in {None, "", "system_overview"} and intent.get("tools"):
        return None
    normalized = text.strip()
    vague_words = ("处理一下", "修一下", "优化一下", "弄一下", "解决一下", "看看问题", "有问题")
    has_target = any(token in normalized for token in ("磁盘", "端口", "日志", "进程", "CPU", "内存", "负载", "资源", "服务", "文件", "异常", "错误", "nginx", "mysql", "sshd", "docker", "8080"))
    if len(normalized) <= 8 and not has_target:
        return "你想检查哪类问题？可以说磁盘、端口、日志、进程或系统资源。"
    if any(word in normalized for word in vague_words) and not has_target:
        return "目标还不明确。请补充要处理的对象，例如端口号、服务名、文件路径或异常现象。"
    return None


def _build_agent_plan(intent: dict[str, Any], text: str) -> list[dict[str, Any]]:
    category = intent.get("category")
    if category == "file_write":
        return [{"phase": "approval", "action": "request_approval", "reason": "写文件属于变更操作，需用户确认"}]
    if intent.get("unsupported"):
        return [{"phase": "stop", "action": "unsupported", "reason": intent.get("unsupported_reason", "没有对应能力")}]

    tools = list(intent.get("tools") or [])
    if category == "system_overview":
        tools = ["get_system_overview", "get_resource_usage", "get_filesystem_usage"]
    if category == "resource_diagnosis":
        tools = ["get_resource_usage", "sample_top_processes"]
    if category == "disk_diagnosis":
        tools = ["get_filesystem_usage", "find_large_files", "find_deleted_open_files"]
    if category == "process_diagnosis":
        tools = ["list_processes", "find_zombie_processes"]
    if category == "network_port_diagnosis":
        tools = ["list_ports"]
    if category == "log_diagnosis":
        tools = ["query_journal"]
    if category == "service_status":
        tools = ["get_service_status", "query_journal"]

    plan = []
    for tool_name in tools:
        plan.append(
            {
                "phase": "collect",
                "tool": tool_name,
                "arguments": _arguments_for_tool(tool_name, text),
                "reason": TOOLS[tool_name].description if tool_name in TOOLS else "采集证据",
            }
        )
    return plan


def _locate_issues(intent: dict[str, Any], tool_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for result in tool_results:
        tool = result.get("tool")
        data = result.get("data") or {}
        if tool == "get_service_status":
            lines = data.get("lines") or []
            service = data.get("service") or "service"
            active_lines = [line for line in lines if "Active:" in line or "Loaded:" in line or "Main PID:" in line]
            error_lines = [line for line in lines if re.search(r"\b(failed|error|denied|refused|timeout|not found|cannot|permission)\b", line, re.IGNORECASE)]
            if data.get("success") is False or error_lines:
                issues.append(
                    {
                        "title": f"{service} 服务状态异常",
                        "where": service,
                        "severity": "high" if data.get("success") is False else "medium",
                        "evidence": error_lines[:5] or active_lines[:5],
                        "raw": lines[:80],
                        "suggestion": "先查看失败日志和配置变更；若需要重启服务，必须走审批。",
                    }
                )
        elif tool in {"query_journal", "query_kernel_log"}:
            lines = data.get("items") or []
            suspicious = [
                line
                for line in lines
                if re.search(r"\b(error|failed|failure|denied|refused|timeout|oom|killed process|segfault|panic|critical|fatal)\b", line, re.IGNORECASE)
                or any(token in line for token in ("错误", "失败", "拒绝", "超时", "异常"))
            ]
            if suspicious:
                issues.append(
                    {
                        "title": "日志中发现异常线索",
                        "where": data.get("unit") or data.get("source") or tool,
                        "severity": "medium",
                        "evidence": suspicious[:5],
                        "raw": lines[-80:],
                        "suggestion": "按日志时间点回溯最近变更，并结合服务状态继续定位。",
                    }
                )
        elif tool == "sample_top_processes":
            items = data.get("items") or []
            hot = [
                item
                for item in items
                if int(item.get("pid") or -1) != 0
                and str(item.get("name") or "").lower() not in {"system idle process", "idle"}
                and (float(item.get("cpu_percent") or 0) >= 50 or float(item.get("memory_percent") or 0) >= 20)
            ]
            if hot:
                top = hot[0]
                issues.append(
                    {
                        "title": f"资源热点进程：{top.get('name')}",
                        "where": f"PID {top.get('pid')}",
                        "severity": "medium",
                        "evidence": [
                            f"PID {item.get('pid')} {item.get('name')} CPU {item.get('cpu_percent')}% MEM {item.get('memory_percent')}% CMD {item.get('cmdline')}"
                            for item in hot[:5]
                        ],
                        "raw": items[:10],
                        "suggestion": "确认该进程是否符合业务预期；终止或重启必须走审批。",
                    }
                )
        elif tool == "get_filesystem_usage":
            hot = [item for item in data.get("items", []) if float(item.get("percent") or 0) >= 80]
            for item in hot[:5]:
                issues.append(
                    {
                        "title": f"磁盘使用率偏高：{item.get('mountpoint')}",
                        "where": item.get("mountpoint"),
                        "severity": "high" if float(item.get("percent") or 0) >= 90 else "medium",
                        "evidence": [f"{item.get('mountpoint')} 使用率 {item.get('percent')}%，设备 {item.get('device')}"],
                        "raw": item,
                        "suggestion": "先查看大文件和已删除但仍占用文件；删除操作必须走审批。",
                    }
                )
        elif tool == "list_ports":
            for item in (data.get("items") or [])[:10]:
                if item.get("pid"):
                    issues.append(
                        {
                            "title": f"端口 {item.get('port')} 被占用",
                            "where": f"{item.get('ip')}:{item.get('port')}",
                            "severity": "low",
                            "evidence": [f"PID {item.get('pid')}，进程 {item.get('process') or 'unknown'}，用户 {item.get('username') or '-'}"],
                            "raw": item,
                            "suggestion": "若需释放端口，点击释放端口并走审批。",
                        }
                    )
    return issues[:8]


def _run_tool_step(trace_id: str, session_id: str, step: dict[str, Any]) -> dict[str, Any]:
    tool_name = step["tool"]
    args = step.get("arguments") or {}
    result = invoke_tool(tool_name, args)
    result["trace_id"] = trace_id
    _record_tool_call(trace_id, result, args)
    record_audit(
        trace_id,
        "tool_call",
        f"调用 Tool：{tool_name}",
        session_id=session_id,
        risk_level=result["risk_level"],
        detail={"arguments": args, "reason": step.get("reason"), "success": result["success"], "duration_ms": result["duration_ms"], "error": result["error"]},
    )
    return result


def _reflect_next_steps(intent: dict[str, Any], text: str, tool_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    executed = {result["tool"] for result in tool_results}
    next_steps: list[dict[str, Any]] = []
    high_disk = False
    high_resource = False

    for result in tool_results:
        data = result.get("data") or {}
        if result["tool"] == "get_filesystem_usage":
            high_disk = any(item.get("percent", 0) >= 90 for item in data.get("items", []))
        if result["tool"] == "get_resource_usage":
            mem = (data.get("memory") or {}).get("percent", 0)
            cpu = data.get("cpu_percent", 0)
            high_resource = cpu >= 80 or mem >= 85

    if high_disk and "find_large_files" not in executed:
        next_steps.append({"phase": "reflect", "tool": "find_large_files", "arguments": _arguments_for_tool("find_large_files", text), "reason": "复盘发现磁盘使用率高，补充扫描大文件"})
    if high_resource and "sample_top_processes" not in executed:
        next_steps.append({"phase": "reflect", "tool": "sample_top_processes", "arguments": {"limit": 8, "interval": 0.2}, "reason": "复盘发现资源压力高，连续采样定位高 CPU/内存进程"})
    if high_resource and "query_journal" not in executed:
        next_steps.append({"phase": "reflect", "tool": "query_journal", "arguments": {"lines": 60}, "reason": "复盘发现资源压力高，补充检查系统错误日志"})
    if high_resource and "query_kernel_log" not in executed:
        next_steps.append({"phase": "reflect", "tool": "query_kernel_log", "arguments": {"lines": 60}, "reason": "复盘发现资源压力高，补充检查内核/OOM/驱动异常"})
    return next_steps


def _zombie_count(tool_results: list[dict[str, Any]]) -> int | None:
    for result in tool_results:
        if result.get("tool") == "find_zombie_processes":
            data = result.get("data") or {}
            return int(data.get("count") or 0)
    return None


def _finalize_intent_after_tools(intent: dict[str, Any], tool_results: list[dict[str, Any]], action_payload: dict[str, Any] | None) -> None:
    if intent.get("category") == "process_diagnosis":
        zombies = _zombie_count(tool_results)
        if zombies == 0:
            intent["risk_level"] = "readonly"
            intent["requires_approval"] = False
            intent["summary"] = "未发现僵尸进程，无需处理"
            return
        if zombies is not None and zombies > 0 and not action_payload:
            intent["requires_approval"] = False
            intent["manual_notice"] = f"发现 {zombies} 个僵尸进程。当前未开放自动 kill 或重启服务；请提供父进程/服务名后再生成受控处理方案。"
            return

    if intent.get("requires_approval") and not action_payload:
        intent["requires_approval"] = False
        intent["manual_notice"] = "已完成只读诊断。当前没有绑定可自动执行的受控动作，所以不创建审批、不执行变更。"


def _parse_file_write_payload(text: str) -> dict[str, Any]:
    filename = "test.txt"
    name_match = re.search(r"([A-Za-z0-9_.-]+\.(?:txt|log|md|json))", text, flags=re.IGNORECASE)
    if name_match:
        filename = name_match.group(1)

    content = ""
    content_patterns = [
        r"(?:里面写|内容是|内容为|写入|写)\s*[“\"']?(.+?)[”\"']?$",
        r"with content\s+[\"']?(.+?)[\"']?$",
    ]
    for pattern in content_patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            content = match.group(1).strip()
            break
    content = content.strip(" ，。\"'“”")
    if not content:
        content = "hello world"
    target = filename
    if "桌面" in text or "desktop" in text.lower():
        target = str(_desktop_root() / filename)
    return {
        "tool_name": "write_text_file_guarded",
        "arguments": {"filename": target, "content": content},
    }


def _wants_port_release(text: str) -> bool:
    lower = text.lower()
    return (
        ("端口" in text or "port" in lower)
        and any(token in text for token in ("释放", "修复", "处理", "关闭", "停止", "kill", "杀掉", "解除占用"))
    )


def _has_port_intent(text: str) -> bool:
    lower = text.lower()
    return "端口" in text or "port" in lower


def _port_release_payload(text: str, tool_results: list[dict[str, Any]]) -> dict[str, Any] | None:
    port = _extract_port(text)
    if not port:
        return None
    for result in tool_results:
        if result.get("tool") != "list_ports" or not result.get("success"):
            continue
        for item in (result.get("data") or {}).get("items", []):
            if int(item.get("port") or 0) == port and item.get("pid"):
                return {
                    "tool_name": "release_port_guarded",
                    "arguments": {"port": port, "pid": item.get("pid"), "process": item.get("process")},
                }
    return None


def _action_payload_for_intent(intent: dict[str, Any], text: str, tool_results: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    if intent["category"] == "file_write":
        return _parse_file_write_payload(text)
    if intent["category"] == "network_port_diagnosis" and _wants_port_release(text):
        return _port_release_payload(text, tool_results or [])
    return None


def _create_approval(
    trace_id: str,
    intent: dict[str, Any],
    text: str,
    action_payload: dict[str, Any] | None = None,
    requester_id: str = "u_system",
) -> dict[str, Any]:
    action_name = action_payload["tool_name"] if action_payload else "controlled_remediation"
    preview = "审批通过后执行受控动作"
    impact = "中风险操作；执行前已进行安全校验，执行结果会写入审计。"
    rollback = "如需回滚，根据审计记录定位生成文件或变更对象后人工处理。"
    if action_payload and action_payload["tool_name"] == "write_text_file_guarded":
        args = action_payload["arguments"]
        preview = f"创建/写入 {args['filename']}"
        impact = "仅写入指定文本文件，不修改系统关键路径。"
        rollback = "删除生成文件即可回滚，文件路径会记录在审计日志。"
    elif action_payload and action_payload["tool_name"] == "release_port_guarded":
        args = action_payload["arguments"]
        preview = f"释放端口 {args['port']}，终止 PID {args.get('pid')} ({args.get('process') or 'unknown'})"
        impact = "会向占用该端口的进程发送 SIGTERM，可能导致对应服务中断。执行前会重新校验 PID 和进程名。"
        rollback = "如需恢复，需要按原服务启动方式重新启动该进程；执行结果和验证状态会记录到审计日志。"

    payload = {
        "trace_id": trace_id,
        "action": action_name,
        "arguments": action_payload["arguments"] if action_payload else {},
    }
    approval = {
        "id": new_id("appr"),
        "trace_id": trace_id,
        "requester_id": requester_id,
        "approver_id": None,
        "status": "pending",
        "risk_level": "high" if (action_payload and action_payload["tool_name"] == "release_port_guarded") or any(token in text for token in ("删除", "rm", "chmod", "chown")) else "medium",
        "action": action_name,
        "command_preview": preview,
        "impact": impact,
        "rollback_plan": rollback,
        "payload_hash": payload_hash(payload),
        "comment": None,
        "expires_at": (datetime.now(timezone.utc).astimezone() + timedelta(hours=1)).isoformat(timespec="seconds"),
        "created_at": now_iso(),
        "decided_at": None,
    }
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO approvals
              (id, trace_id, requester_id, approver_id, status, risk_level, action, command_preview, impact, rollback_plan, payload_hash, comment, expires_at, created_at, decided_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(approval.values()),
        )
        if action_payload:
            conn.execute(
                """
                INSERT OR REPLACE INTO approval_payloads
                  (approval_id, trace_id, tool_name, arguments, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    approval["id"],
                    trace_id,
                    action_payload["tool_name"],
                    json.dumps(action_payload["arguments"], ensure_ascii=False),
                    now_iso(),
                ),
            )
    record_audit(
        trace_id,
        "approval_created",
        "中高风险操作已生成审批任务",
        risk_level=approval["risk_level"],
        detail={"approval_id": approval["id"], "action": approval["action"], "payload_hash": approval["payload_hash"], "action_payload": action_payload},
    )
    return approval


def _format_knowledge_refs(refs: list[dict[str, Any]]) -> str:
    if not refs:
        return ""
    lines = []
    for item in refs[:3]:
        lines.append(f"[{item.get('layer_name')}] {item.get('title')}")
    return "\n引用：" + "；".join(lines)


def _summarize(
    intent: dict[str, Any],
    security: dict[str, Any],
    tool_results: list[dict[str, Any]],
    approval: dict[str, Any] | None,
    issues: list[dict[str, Any]] | None = None,
    knowledge_refs: list[dict[str, Any]] | None = None,
) -> str:
    ref_text = _format_knowledge_refs(knowledge_refs or [])
    if not security["allowed"]:
        rules = "、".join(rule["name"] for rule in security["matched_rules"]) or "安全规则"
        return f"已拦截：{rules}。\n未执行任何操作。{ref_text}"
    if intent.get("unsupported"):
        return f"暂不支持：{intent.get('unsupported_reason', '当前版本没有对应执行能力')}{ref_text}"
    if intent.get("manual_notice"):
        return intent["manual_notice"] + ref_text
    if approval:
        return f"需要审批：{approval['command_preview']}。\n审批通过后我会继续执行。{ref_text}"
    if intent.get("category") == "network_port_diagnosis":
        port_result = next((result for result in tool_results if result.get("tool") == "list_ports"), None)
        ports = ((port_result or {}).get("data") or {}).get("items", [])
        if ports:
            sample = []
            for item in ports[:12]:
                proc = item.get("process") or "unknown"
                pid = item.get("pid") or "-"
                user = item.get("username") or "-"
                sample.append(f"{item.get('ip')}:{item.get('port')} -> {proc}(PID {pid}, 用户 {user})")
            return (
                f"结论：当前发现 {len(ports)} 个监听端口。\n"
                f"端口清单：{'；'.join(sample)}\n"
                f"建议：如需释放某个端口，请指定端口号；高风险释放会先进入审批。{ref_text}"
            )
        return f"结论：当前未发现监听端口。\n建议：如需排查连接状态，可继续指定端口号或服务名。{ref_text}"
    if issues:
        first = issues[0]
        return (
            f"结论：定位到 {first['title']}，位置：{first.get('where') or '-'}。\n"
            f"证据：{'; '.join(str(item) for item in first.get('evidence', [])[:3]) or '见原始日志'}\n"
            f"建议：{first.get('suggestion') or '请结合原始证据继续排查。'}{ref_text}"
        )

    evidence = []
    for result in tool_results:
        name = result["tool"]
        data = result.get("data") or {}
        if name == "get_filesystem_usage":
            hot = [item for item in data.get("items", []) if item.get("percent", 0) >= 80]
            evidence.append(f"磁盘挂载点 {len(data.get('items', []))} 个，高使用率 {len(hot)} 个")
        elif name == "find_large_files":
            evidence.append(f"发现大文件 {len(data.get('items', []))} 个")
        elif name == "find_deleted_open_files":
            evidence.append(f"open deleted files {data.get('count', 0)}")
        elif name == "find_zombie_processes":
            evidence.append(f"僵尸进程 {data.get('count', 0)} 个")
        elif name == "list_ports":
            ports = data.get("items", [])
            if ports:
                sample = []
                for item in ports[:8]:
                    proc = item.get("process") or "unknown"
                    pid = item.get("pid") or "-"
                    sample.append(f"{item.get('ip')}:{item.get('port')} -> {proc}(PID {pid})")
                evidence.append(f"监听端口 {data.get('count', 0)} 个：" + "；".join(sample))
            else:
                evidence.append("未发现监听端口")
        elif name == "query_journal":
            evidence.append(f"日志线索 {len(data.get('items', []))} 条")
        elif name == "query_kernel_log":
            evidence.append(f"内核日志线索 {len(data.get('items', []))} 条")
        elif name == "get_resource_usage":
            evidence.append(f"CPU {data.get('cpu_percent')}%，内存 {data.get('memory', {}).get('percent')}%")
        elif name == "sample_top_processes":
            top = []
            visible_items = [
                item
                for item in data.get("items", [])
                if int(item.get("pid") or -1) != 0
                and str(item.get("name") or "").lower() not in {"system idle process", "idle"}
            ]
            for item in visible_items[:5]:
                top.append(f"{item.get('name')}[PID {item.get('pid')}] CPU {item.get('cpu_percent')}% MEM {item.get('memory_percent')}%")
            evidence.append("Top 进程：" + ("；".join(top) if top else "无可见进程样本"))
        elif name == "get_system_overview":
            evidence.append(f"主机 {data.get('host')}，架构 {data.get('arch')}")

    advice = {
        "disk_diagnosis": "建议先压缩或轮转日志，再评估是否删除；删除必须经过路径策略和人工审批。",
        "process_diagnosis": "若存在僵尸进程，应定位父进程；重启服务属于中高风险动作，需要审批。",
        "network_port_diagnosis": "如需定位单个端口，可继续指定端口号；涉及停止进程或重启服务时会先进入审批。",
        "resource_diagnosis": "优先确认 Top 进程是否符合业务预期；若需终止进程或重启服务，必须走审批并在执行后复查资源曲线。",
        "log_diagnosis": "优先按服务聚合错误日志，结合时间窗口和最近变更定位根因。",
        "system_overview": "如需修复，请指定对象；变更操作会先申请审批。",
    }.get(intent["category"], "建议继续采集证据后再执行操作。")

    response = [
        f"结论：{intent['summary']}。",
        "证据：" + ("；".join(evidence) if evidence else "暂无异常证据"),
        "建议：" + advice + ref_text,
    ]
    return "\n".join(response)


def _has_port_intent(text: str) -> bool:
    lower = text.lower()
    return "端口" in text or "port" in lower


def _is_strong_ops_intent(intent: dict[str, Any], text: str) -> bool:
    category = intent.get("category")
    if category in {
        "disk_diagnosis",
        "process_diagnosis",
        "network_port_diagnosis",
        "log_diagnosis",
        "resource_diagnosis",
        "service_status",
    }:
        return True
    lower = text.lower()
    return any(
        token in text
        for token in ("端口", "磁盘", "日志", "进程", "内存", "负载", "服务", "异常", "错误")
    ) or any(token in lower for token in ("port", "cpu", "memory", "load", "disk", "error", "journal", "nginx", "mysql", "sshd"))


def handle_chat(content: str, session_id: str | None = None, user_id: str = "u_system") -> dict[str, Any]:
    sid = ensure_session(session_id, title=content[:24] or "安全运维会话")
    trace_id = new_id("tr")
    context = _recent_context(sid)
    _save_message(sid, trace_id, "user", content)
    record_audit(trace_id, "user_message", "收到自然语言运维请求", session_id=sid, user_id=user_id, detail={"content": content, "recent_context": context[-3:]})

    security = check_text(content)
    _record_security_check(trace_id, content, security)
    record_audit(
        trace_id,
        "security_check",
        "完成提示词注入和危险指令校验",
        session_id=sid,
        risk_level=security["risk_level"],
        detail=security,
    )

    fallback_intent = classify_intent(content)
    llm_plan = {"used": False, "intent": fallback_intent, "error": None}
    if (
        security["allowed"]
        and not fallback_intent.get("unsupported")
        and fallback_intent["category"] not in {"file_write"}
        and not _is_strong_ops_intent(fallback_intent, content)
    ):
        llm_plan = plan_with_deepseek(content, fallback_intent)
    intent = llm_plan["intent"]
    if _has_port_intent(content):
        intent["category"] = "network_port_diagnosis"
        intent["summary"] = "分析网络监听端口和进程归属"
        intent["tools"] = ["list_ports"]
        if _wants_port_release(content):
            intent["risk_level"] = "medium"
            intent["requires_approval"] = True
        else:
            intent["risk_level"] = "readonly"
            intent["requires_approval"] = False
    knowledge_refs = retrieve_knowledge(
        " ".join([content, intent.get("category", ""), intent.get("summary", "")]),
        limit=5,
        trace_id=trace_id,
        session_id=sid,
    ) if security["allowed"] else []
    if security["risk_level"] == "forbidden":
        intent["risk_level"] = "forbidden"
        intent["requires_approval"] = False
    clarification = _needs_clarification(content, intent) if security["allowed"] else None
    if clarification:
        intent["category"] = "clarification"
        intent["risk_level"] = "readonly"
        intent["requires_approval"] = False
        intent["tools"] = []
    record_audit(
        trace_id,
        "llm_plan",
        "生成结构化运维计划",
        session_id=sid,
        risk_level=intent["risk_level"],
        detail={
            "provider": "deepseek" if llm_plan.get("used") else "local_rules",
            "llm_status": get_llm_status(),
            "llm_error": llm_plan.get("error"),
            "intent": intent,
            "clarification": clarification,
        },
    )

    tool_results: list[dict[str, Any]] = []
    approval = None
    action_payload = _action_payload_for_intent(intent, content)
    agent_plan = _build_agent_plan(intent, content)
    record_audit(trace_id, "agent_plan", "Agent 已生成执行计划", session_id=sid, risk_level=intent["risk_level"], detail={"plan": agent_plan})
    if security["allowed"] and not clarification and not intent.get("unsupported") and intent["category"] != "file_write":
        for step in agent_plan:
            if step.get("tool"):
                tool_results.append(_run_tool_step(trace_id, sid, step))
        reflect_steps = _reflect_next_steps(intent, content, tool_results)
        if reflect_steps:
            record_audit(trace_id, "agent_reflection", "Agent 复盘后补充采集", session_id=sid, risk_level=intent["risk_level"], detail={"next_steps": reflect_steps})
            for step in reflect_steps:
                tool_results.append(_run_tool_step(trace_id, sid, step))
    if not action_payload:
        action_payload = _action_payload_for_intent(intent, content, tool_results)
    if _wants_port_release(content) and not action_payload:
        intent["manual_notice"] = "我已经完成端口诊断，但没有找到可安全释放的目标进程。请确认端口号仍被占用后再重试。"
    if action_payload:
        intent["requires_approval"] = True
        intent["risk_level"] = "high" if action_payload["tool_name"] == "release_port_guarded" else intent.get("risk_level", "medium")
    _finalize_intent_after_tools(intent, tool_results, action_payload)
    if security["allowed"] and not clarification and action_payload and (intent["requires_approval"] or security["action"] in {"approval", "review"}):
        approval = _create_approval(trace_id, intent, content, action_payload, requester_id=user_id)

    issues = _locate_issues(intent, tool_results)
    if issues:
        record_audit(trace_id, "issue_located", "Agent 已定位异常点和证据", session_id=sid, risk_level=issues[0].get("severity"), detail={"issues": issues})
    fallback_answer = clarification or _summarize(intent, security, tool_results, approval, issues, knowledge_refs)
    if clarification or approval or issues or intent.get("unsupported") or intent.get("manual_notice"):
        llm_summary = {"used": False, "answer": fallback_answer, "error": "local concise response"}
    else:
        llm_summary = summarize_with_deepseek(
            user_text=content,
            intent=intent,
            security=security,
            tool_results=tool_results,
            approval=approval,
            fallback_answer=fallback_answer,
            knowledge_refs=knowledge_refs,
        )
    answer = llm_summary["answer"]
    if knowledge_refs and "引用：" not in answer:
        answer = answer.rstrip() + _format_knowledge_refs(knowledge_refs)
    learned_knowledge = []
    if security["allowed"] and not clarification:
        learned_knowledge = learn_from_chat(
            trace_id=trace_id,
            session_id=sid,
            user_text=content,
            answer=answer,
            intent=intent,
            tool_results=tool_results,
            issues=issues,
            approval=approval,
        )
    _save_message(sid, trace_id, "assistant", answer, {"intent": intent, "security": security})
    record_audit(
        trace_id,
        "agent_response",
        "Agent 已生成可解释答复",
        session_id=sid,
        risk_level=intent["risk_level"],
        detail={
            "provider": "deepseek" if llm_summary.get("used") else "local_rules",
            "llm_error": llm_summary.get("error"),
            "answer": answer,
            "issues": issues,
            "knowledge_refs": [{"id": item["id"], "layer": item["layer"], "title": item["title"], "score": item.get("score")} for item in knowledge_refs],
            "learned_knowledge": [{"id": item["id"], "layer": item["layer"], "title": item["title"]} for item in learned_knowledge],
        },
    )
    return {
        "session_id": sid,
        "trace_id": trace_id,
        "status": "blocked" if not security["allowed"] else "needs_clarification" if clarification else "unsupported" if intent.get("unsupported") else "pending_approval" if approval else "succeeded",
        "agent_mode": {
            "planner": "deepseek" if llm_plan.get("used") else "local_rules",
            "summarizer": "deepseek" if llm_summary.get("used") else "local_rules",
            "llm_error": llm_plan.get("error") or llm_summary.get("error"),
        },
        "intent": intent,
        "plan": agent_plan,
        "security": security,
        "tool_results": tool_results,
        "issues": issues,
        "knowledge_refs": knowledge_refs,
        "learned_knowledge": learned_knowledge,
        "approval": approval,
        "answer": answer,
    }


def get_dashboard() -> dict[str, Any]:
    overview = invoke_tool("get_system_overview", {})
    resources = invoke_tool("get_resource_usage", {})
    disks = invoke_tool("get_filesystem_usage", {})
    ports = invoke_tool("list_ports", {})
    return {"overview": overview["data"], "resources": resources["data"], "disks": disks["data"], "ports": ports["data"]}


def get_tools() -> dict[str, Any]:
    return {"items": list_tool_metadata()}


def get_model_status() -> dict[str, Any]:
    return get_llm_status()


def _count_rows(conn, table: str, where: str = "", params: tuple[Any, ...] = ()) -> int:
    row = conn.execute(f"SELECT COUNT(*) AS count FROM {table} {where}", params).fetchone()
    return int(row["count"] if row else 0)


def get_stats() -> dict[str, Any]:
    dashboard = get_dashboard()
    tools = list_tool_metadata()
    knowledge = knowledge_stats()
    model = get_model_status()
    today_start = datetime.now(timezone.utc).astimezone().replace(hour=0, minute=0, second=0, microsecond=0).isoformat(timespec="seconds")
    with connect() as conn:
        audit_total = _count_rows(conn, "audit_events")
        audit_today = _count_rows(conn, "audit_events", "WHERE created_at >= ?", (today_start,))
        trace_total = _count_rows(conn, "(SELECT DISTINCT trace_id FROM audit_events)")
        trace_today = _count_rows(conn, "(SELECT DISTINCT trace_id FROM audit_events WHERE created_at >= ?)", "", (today_start,))
        message_total = _count_rows(conn, "messages")
        user_message_total = _count_rows(conn, "messages", "WHERE role = ?", ("user",))
        user_message_today = _count_rows(conn, "messages", "WHERE role = ? AND created_at >= ?", ("user", today_start))
        assistant_message_total = _count_rows(conn, "messages", "WHERE role = ?", ("assistant",))
        assistant_message_today = _count_rows(conn, "messages", "WHERE role = ? AND created_at >= ?", ("assistant", today_start))
        sessions_total = _count_rows(conn, "sessions")
        sessions_today = _count_rows(conn, "sessions", "WHERE created_at >= ?", (today_start,))
        tool_call_total = _count_rows(conn, "tool_calls")
        tool_call_today = _count_rows(conn, "tool_calls", "WHERE created_at >= ?", (today_start,))
        tool_success_total = _count_rows(conn, "tool_calls", "WHERE status = ?", ("succeeded",))
        tool_success_today = _count_rows(conn, "tool_calls", "WHERE status = ? AND created_at >= ?", ("succeeded", today_start))
        model_call_total = _count_rows(conn, "audit_events", "WHERE event_type = ?", ("llm_plan",))
        model_call_today = _count_rows(conn, "audit_events", "WHERE event_type = ? AND created_at >= ?", ("llm_plan", today_start))
        approval_total = _count_rows(conn, "approvals")
        approval_pending = _count_rows(conn, "approvals", "WHERE status = ?", ("pending",))
        approval_approved = _count_rows(conn, "approvals", "WHERE status = ?", ("approved",))
        approval_rejected = _count_rows(conn, "approvals", "WHERE status = ?", ("rejected",))
        approval_expired = _count_rows(conn, "approvals", "WHERE status = ?", ("expired",))
        risk_rows = conn.execute(
            "SELECT COALESCE(risk_level, 'none') AS risk, COUNT(*) AS count FROM audit_events GROUP BY COALESCE(risk_level, 'none')"
        ).fetchall()
        risk_today_rows = conn.execute(
            "SELECT COALESCE(risk_level, 'none') AS risk, COUNT(*) AS count FROM audit_events WHERE created_at >= ? GROUP BY COALESCE(risk_level, 'none')",
            (today_start,),
        ).fetchall()
        event_rows = conn.execute(
            "SELECT event_type, COUNT(*) AS count FROM audit_events GROUP BY event_type ORDER BY count DESC LIMIT 12"
        ).fetchall()
        latest_audit = rows_to_dicts(conn.execute("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 10").fetchall())
    risk_counts = {row["risk"]: int(row["count"]) for row in risk_rows}
    risk_today_counts = {row["risk"]: int(row["count"]) for row in risk_today_rows}
    event_counts = {row["event_type"]: int(row["count"]) for row in event_rows}
    risky_total = sum(risk_counts.get(level, 0) for level in ("medium", "high", "forbidden"))
    risky_today = sum(risk_today_counts.get(level, 0) for level in ("medium", "high", "forbidden"))
    enabled_tools = len([tool for tool in tools if tool.get("enabled")])
    tool_success_rate = round(tool_success_total / tool_call_total * 100, 1) if tool_call_total else 100.0
    completion_rate = round(assistant_message_total / user_message_total * 100, 1) if user_message_total else 100.0
    db_bytes = DB_PATH.stat().st_size if DB_PATH.exists() else 0
    audit_bytes = AUDIT_JSONL_PATH.stat().st_size if AUDIT_JSONL_PATH.exists() else 0
    return {
        "dashboard": dashboard,
        "model": model,
        "audit": {
            "total": audit_total,
            "today": audit_today,
            "traces": trace_total,
            "traces_today": trace_today,
            "risk_counts": risk_counts,
            "risk_counts_today": risk_today_counts,
            "event_counts": event_counts,
            "risky_total": risky_total,
            "risky_today": risky_today,
            "latest": latest_audit,
            "storage_bytes": db_bytes + audit_bytes,
            "db_bytes": db_bytes,
            "jsonl_bytes": audit_bytes,
        },
        "chat": {
            "sessions": sessions_total,
            "sessions_today": sessions_today,
            "messages": message_total,
            "user_messages": user_message_total,
            "user_messages_today": user_message_today,
            "assistant_messages": assistant_message_total,
            "assistant_messages_today": assistant_message_today,
            "completion_rate": completion_rate,
        },
        "tools": {
            "total": len(tools),
            "enabled": enabled_tools,
            "disabled": len(tools) - enabled_tools,
            "calls": tool_call_total,
            "calls_today": tool_call_today,
            "success": tool_success_total,
            "success_today": tool_success_today,
            "success_rate": tool_success_rate,
        },
        "model_usage": {
            "calls": model_call_total,
            "calls_today": model_call_today,
        },
        "approvals": {
            "total": approval_total,
            "pending": approval_pending,
            "approved": approval_approved,
            "rejected": approval_rejected,
            "expired": approval_expired,
        },
        "knowledge": knowledge,
    }


def get_knowledge(layer: str | None = None, query: str | None = None, limit: int = 80) -> dict[str, Any]:
    return list_knowledge_items(layer=layer, query=query, limit=limit)


def get_knowledge_stats() -> dict[str, Any]:
    return knowledge_stats()


def get_audit(
    limit: int = 80,
    trace_id: str | None = None,
    user_id: str | None = None,
    risk_level: str | None = None,
    event_type: str | None = None,
    tool_name: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, Any]:
    where = []
    params: list[Any] = []
    if trace_id:
        where.append("trace_id = ?")
        params.append(trace_id)
    if user_id:
        where.append("user_id = ?")
        params.append(user_id)
    if risk_level:
        where.append("risk_level = ?")
        params.append(risk_level)
    if event_type:
        where.append("event_type = ?")
        params.append(event_type)
    if date_from:
        where.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        where.append("created_at <= ?")
        params.append(date_to)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    params.append(limit)
    with connect() as conn:
        rows = conn.execute(f"SELECT * FROM audit_events{clause} ORDER BY created_at DESC LIMIT ?", tuple(params)).fetchall()
        items = rows_to_dicts(rows)
        if tool_name:
            items = [item for item in items if item.get("detail") and item["detail"].get("arguments") is not None and tool_name in json.dumps(item["detail"], ensure_ascii=False)]
    if trace_id:
        items = list(reversed(items))
    return {"items": items}


def _phase_for_event(event_type: str) -> tuple[str, int]:
    mapping = {
        "user_message": ("用户请求", 1),
        "security_check": ("安全检查", 2),
        "llm_plan": ("AI 分析", 3),
        "knowledge_retrieved": ("知识库检索", 4),
        "agent_plan": ("执行计划", 5),
        "tool_call": ("执行命令", 6),
        "agent_reflection": ("复盘补采", 7),
        "issue_located": ("问题定位", 8),
        "approval_created": ("审批创建", 9),
        "approval_decided": ("审批决策", 10),
        "execution_result": ("执行结果", 11),
        "knowledge_learned": ("知识沉淀", 12),
        "agent_response": ("返回结果", 13),
    }
    return mapping.get(event_type, ("审计事件", 50))


def _build_closure_report(
    trace_id: str,
    events: list[dict[str, Any]],
    security: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    approvals: list[dict[str, Any]],
    messages: list[dict[str, Any]],
) -> dict[str, Any]:
    event_types = {event.get("event_type") for event in events}
    learned_items: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    final_answer = ""
    intent_category = "-"
    risk_level = "none"
    for event in events:
        detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
        if event.get("event_type") == "llm_plan":
            intent = detail.get("intent") if isinstance(detail.get("intent"), dict) else {}
            intent_category = intent.get("category") or intent_category
            risk_level = intent.get("risk_level") or event.get("risk_level") or risk_level
        elif event.get("event_type") == "issue_located":
            issues = detail.get("issues") if isinstance(detail.get("issues"), list) else issues
        elif event.get("event_type") == "knowledge_learned":
            learned_items = detail.get("items") if isinstance(detail.get("items"), list) else learned_items
        elif event.get("event_type") == "agent_response":
            final_answer = str(detail.get("answer") or "")[:800]
            risk_level = event.get("risk_level") or risk_level

    user_request = next((msg.get("content") for msg in messages if msg.get("role") == "user"), "")
    blocked = any(check.get("allowed") == 0 for check in security) or any(event.get("risk_level") == "forbidden" for event in events)
    pending = any(item.get("status") == "pending" for item in approvals)
    executed_after_approval = any(event.get("event_type") == "execution_result" for event in events)
    failed_tools = [tool for tool in tools if tool.get("status") != "succeeded"]
    phases = [
        {"name": "发现异常", "done": bool(user_request), "evidence": user_request[:120] or "无用户请求"},
        {"name": "AI分析", "done": "llm_plan" in event_types, "evidence": intent_category},
        {"name": "安全过滤", "done": bool(security), "evidence": "已拦截" if blocked else "通过护栏"},
        {"name": "Tool执行", "done": bool(tools), "evidence": f"{len(tools)} 次调用，失败 {len(failed_tools)} 次"},
        {"name": "审批闭环", "done": bool(approvals) or not pending, "evidence": "无须审批" if not approvals else f"{len(approvals)} 条审批，{'待处理' if pending else '已决策'}"},
        {"name": "自动验证", "done": bool(issues) or bool(tools) or blocked, "evidence": f"{len(issues)} 个问题点" if issues else ("请求已拦截" if blocked else "未发现明确异常")},
        {"name": "知识沉淀", "done": bool(learned_items), "evidence": f"{len(learned_items)} 条新知识" if learned_items else "本次未新增"},
        {"name": "生成报告", "done": True, "evidence": trace_id},
    ]
    completed = sum(1 for phase in phases if phase["done"])
    status = "blocked" if blocked else "pending_approval" if pending else "remediated" if executed_after_approval else "diagnosed"
    next_actions = []
    if pending:
        next_actions.append("审批中心确认后继续执行受控修复")
    if failed_tools:
        next_actions.append("检查失败 Tool 的权限、白名单或运行环境")
    if issues and not pending:
        next_actions.append("按定位证据选择受控修复动作")
    if not next_actions:
        next_actions.append("保留 trace 作为审计证据，并将有效经验沉淀到知识库")
    return {
        "trace_id": trace_id,
        "status": status,
        "completion_percent": round(completed / len(phases) * 100),
        "user_request": user_request,
        "intent_category": intent_category,
        "risk_level": risk_level,
        "phases": phases,
        "tool_summary": {
            "total": len(tools),
            "succeeded": len([tool for tool in tools if tool.get("status") == "succeeded"]),
            "failed": len(failed_tools),
            "names": [tool.get("tool_name") for tool in tools],
        },
        "approval_summary": {
            "total": len(approvals),
            "pending": len([item for item in approvals if item.get("status") == "pending"]),
            "approved": len([item for item in approvals if item.get("status") == "approved"]),
            "rejected": len([item for item in approvals if item.get("status") == "rejected"]),
        },
        "knowledge_summary": {
            "learned_count": len(learned_items),
            "items": learned_items[:6],
        },
        "issue_summary": issues[:5],
        "final_answer": final_answer,
        "next_actions": next_actions,
    }


def get_audit_trace(trace_id: str) -> dict[str, Any]:
    with connect() as conn:
        audit_rows = conn.execute("SELECT * FROM audit_events WHERE trace_id = ? ORDER BY created_at ASC", (trace_id,)).fetchall()
        security_rows = conn.execute("SELECT * FROM security_checks WHERE trace_id = ? ORDER BY created_at ASC", (trace_id,)).fetchall()
        tool_rows = conn.execute("SELECT * FROM tool_calls WHERE trace_id = ? ORDER BY created_at ASC", (trace_id,)).fetchall()
        approval_rows = conn.execute("SELECT * FROM approvals WHERE trace_id = ? ORDER BY created_at ASC", (trace_id,)).fetchall()
        message_rows = conn.execute("SELECT * FROM messages WHERE trace_id = ? ORDER BY created_at ASC", (trace_id,)).fetchall()

    events = rows_to_dicts(audit_rows)
    security = rows_to_dicts(security_rows)
    tools = rows_to_dicts(tool_rows)
    approvals = rows_to_dicts(approval_rows)
    messages = rows_to_dicts(message_rows)
    timeline = []
    for event in events:
        phase, order = _phase_for_event(event.get("event_type", ""))
        detail = event.get("detail") if isinstance(event.get("detail"), dict) else {}
        timeline.append(
            {
                "phase": phase,
                "order": order,
                "event_type": event.get("event_type"),
                "summary": event.get("summary"),
                "risk_level": event.get("risk_level"),
                "created_at": event.get("created_at"),
                "detail": detail,
            }
        )
    timeline.sort(key=lambda item: (item["created_at"] or "", item["order"]))
    closure_report = _build_closure_report(trace_id, events, security, tools, approvals, messages)
    return {
        "trace_id": trace_id,
        "complete_chain": [
            "用户请求",
            "安全检查",
            "AI 分析",
            "知识库检索",
            "执行计划",
            "执行命令",
            "问题定位",
            "返回结果",
            "写入日志",
        ],
        "timeline": timeline,
        "messages": messages,
        "security_checks": security,
        "tool_calls": tools,
        "approvals": approvals,
        "event_count": len(events),
        "tool_count": len(tools),
        "approval_count": len(approvals),
        "closure_report": closure_report,
    }


def get_approvals() -> dict[str, Any]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM approvals ORDER BY created_at DESC LIMIT 80").fetchall()
    return {"items": rows_to_dicts(rows)}


def decide_approval(approval_id: str, approved: bool, comment: str = "", approver_id: str = "u_system") -> dict[str, Any]:
    status = "approved" if approved else "rejected"
    with connect() as conn:
        conn.execute(
            "UPDATE approvals SET status = ?, approver_id = ?, comment = ?, decided_at = ? WHERE id = ?",
            (status, approver_id, comment, now_iso(), approval_id),
        )
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        payload_row = conn.execute("SELECT * FROM approval_payloads WHERE approval_id = ?", (approval_id,)).fetchone()
    if not row:
        return {"success": False, "error": {"code": "APPROVAL_NOT_FOUND", "message": "审批不存在"}}
    approval = rows_to_dicts([row])[0]
    record_audit(
        approval["trace_id"],
        "approval_decided",
        f"审批已{('通过' if approved else '拒绝')}",
        risk_level=approval["risk_level"],
        user_id=approver_id,
        detail={"approval_id": approval_id, "status": status, "comment": comment, "approver_id": approver_id},
    )
    execution = None
    if approved and payload_row:
        payload = rows_to_dicts([payload_row])[0]
        arguments = payload["arguments"]
        arguments["approval_id"] = approval_id
        execution = invoke_tool(payload["tool_name"], arguments)
        _record_tool_call(approval["trace_id"], execution, arguments)
        record_audit(
            approval["trace_id"],
            "execution_result",
            f"审批后执行 Tool：{payload['tool_name']}",
            risk_level=execution["risk_level"],
            detail={"arguments": arguments, "result": execution},
        )
    return {"success": True, "item": approval, "execution": execution}


def decide_approval_safe(approval_id: str, approved: bool, comment: str = "", approver_id: str = "u_system") -> dict[str, Any]:
    now = datetime.now(timezone.utc).astimezone()
    with connect() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        payload_row = conn.execute("SELECT * FROM approval_payloads WHERE approval_id = ?", (approval_id,)).fetchone()
        if not row:
            return {"success": False, "error": {"code": "APPROVAL_NOT_FOUND", "message": "approval not found"}}
        approval = rows_to_dicts([row])[0]
        if approval["status"] != "pending":
            return {"success": False, "error": {"code": "SEC_APPROVAL_INVALID", "message": "approval already decided"}, "item": approval}
        try:
            expires_at = datetime.fromisoformat(str(approval["expires_at"]))
        except ValueError:
            return {"success": False, "error": {"code": "SEC_APPROVAL_INVALID", "message": "invalid approval expiry"}, "item": approval}
        if expires_at < now:
            conn.execute(
                "UPDATE approvals SET status = ?, approver_id = ?, comment = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                ("expired", approver_id, comment, now_iso(), approval_id),
            )
            approval["status"] = "expired"
            return {"success": False, "error": {"code": "SEC_APPROVAL_INVALID", "message": "approval expired"}, "item": approval}
        if approved and not payload_row:
            return {"success": False, "error": {"code": "SEC_APPROVAL_INVALID", "message": "missing approval payload"}, "item": approval}
        if approved and payload_row:
            payload_for_check = rows_to_dicts([payload_row])[0]
            expected_hash = payload_hash(
                {
                    "trace_id": approval["trace_id"],
                    "action": payload_for_check["tool_name"],
                    "arguments": payload_for_check["arguments"],
                }
            )
            if expected_hash != approval["payload_hash"]:
                conn.execute(
                    "UPDATE approvals SET status = ?, approver_id = ?, comment = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                    ("rejected", approver_id, "payload hash mismatch", now_iso(), approval_id),
                )
                approval["status"] = "rejected"
                return {"success": False, "error": {"code": "SEC_APPROVAL_INVALID", "message": "payload hash mismatch"}, "item": approval}
        status = "approved" if approved else "rejected"
        updated = conn.execute(
            "UPDATE approvals SET status = ?, approver_id = ?, comment = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
            (status, approver_id, comment, now_iso(), approval_id),
        )
        if updated.rowcount != 1:
            return {"success": False, "error": {"code": "SEC_APPROVAL_INVALID", "message": "approval already decided"}, "item": approval}
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        approval = rows_to_dicts([row])[0]

    record_audit(
        approval["trace_id"],
        "approval_decided",
        "approval approved" if approved else "approval rejected",
        risk_level=approval["risk_level"],
        user_id=approver_id,
        detail={"approval_id": approval_id, "status": status, "comment": comment, "approver_id": approver_id},
    )
    execution = None
    if approved and payload_row:
        payload = rows_to_dicts([payload_row])[0]
        arguments = dict(payload["arguments"])
        arguments["approval_id"] = approval_id
        execution = invoke_tool(payload["tool_name"], arguments)
        _record_tool_call(approval["trace_id"], execution, arguments)
        record_audit(
            approval["trace_id"],
            "execution_result",
            f"approval execution tool {payload['tool_name']}",
            risk_level=execution["risk_level"],
            detail={"arguments": arguments, "result": execution},
        )
    return {"success": True, "item": approval, "execution": execution}


def invoke_registered_tool(name: str, arguments: dict[str, Any], trace_id: str | None = None) -> dict[str, Any]:
    tid = trace_id or new_id("tr")
    tool = TOOLS.get(name)
    if not tool:
        return {"trace_id": tid, "success": False, "error": {"code": "TOOL_NOT_FOUND", "message": "Tool 未注册"}}
    command_like = json.dumps(arguments, ensure_ascii=False)
    security = check_text(command_like, input_type="tool_arguments")
    _record_security_check(tid, command_like, security)
    if not security["allowed"]:
        record_audit(tid, "security_check", "Tool 参数被安全护栏拦截", risk_level=security["risk_level"], detail=security)
        return {"trace_id": tid, "success": False, "error": {"code": security["error_code"], "message": "Tool 参数未通过安全校验"}, "security": security}
    result = invoke_tool(name, arguments)
    result["trace_id"] = tid
    _record_tool_call(tid, result, arguments)
    record_audit(tid, "tool_call", f"手动调用 Tool：{name}", risk_level=result["risk_level"], detail={"arguments": arguments, "success": result["success"]})
    return result
