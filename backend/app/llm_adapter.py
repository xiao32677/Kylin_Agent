from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"

READONLY_TOOLS = {
    "get_system_overview",
    "get_resource_usage",
    "get_filesystem_usage",
    "find_large_files",
    "find_deleted_open_files",
    "list_processes",
    "sample_top_processes",
    "find_zombie_processes",
    "list_ports",
    "query_journal",
    "query_kernel_log",
    "get_service_status",
}

VALID_CATEGORIES = {
    "disk_diagnosis",
    "process_diagnosis",
    "network_port_diagnosis",
    "log_diagnosis",
    "system_overview",
    "resource_diagnosis",
    "service_status",
    "file_write",
    "unsupported_file_write",
    "unsupported_config_change",
    "unsupported_service_mutation",
}

VALID_RISK = {"readonly", "low", "medium", "high", "forbidden"}


def get_llm_status() -> dict[str, Any]:
    api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    base_url = os.environ.get("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
    model = os.environ.get("DEEPSEEK_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    return {
        "provider": "deepseek",
        "configured": bool(api_key),
        "base_url": base_url,
        "model": model,
        "mode": "external_llm" if api_key else "local_rules_fallback",
    }


def _post_chat(messages: list[dict[str, str]], *, timeout: int = 20, max_tokens: int = 900) -> dict[str, Any]:
    status = get_llm_status()
    if not status["configured"]:
        return {"success": False, "error": "DEEPSEEK_API_KEY is not configured"}

    endpoint = status["base_url"].rstrip("/") + "/chat/completions"
    payload = {
        "model": status["model"],
        "messages": messages,
        "stream": False,
        "max_tokens": max_tokens,
        "thinking": {"type": "disabled"},
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['DEEPSEEK_API_KEY'].strip()}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err = exc.read().decode("utf-8", errors="replace")
        return {"success": False, "error": f"HTTP {exc.code}: {err[:300]}"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}

    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return {"success": False, "error": "unexpected DeepSeek response shape", "raw": data}
    return {"success": True, "content": content, "raw": data}


def _extract_json(content: str) -> dict[str, Any] | None:
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if "\n" in text:
            text = text.split("\n", 1)[1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None


def _validate_plan(plan: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    category = str(plan.get("category") or plan.get("intent") or fallback["category"])
    if category not in VALID_CATEGORIES:
        category = fallback["category"]

    risk_level = str(plan.get("risk_level") or fallback["risk_level"])
    if risk_level not in VALID_RISK:
        risk_level = fallback["risk_level"]

    tools = plan.get("tools")
    if not isinstance(tools, list):
        tools = fallback["tools"]
    clean_tools = []
    for item in tools:
        name = item.get("name") if isinstance(item, dict) else item
        if name in READONLY_TOOLS and name not in clean_tools:
            clean_tools.append(name)
    if not clean_tools:
        clean_tools = fallback["tools"]

    summary = str(plan.get("summary") or fallback["summary"])[:220]
    requires_approval = bool(plan.get("requires_approval", fallback["requires_approval"]))
    if risk_level in {"medium", "high"}:
        requires_approval = True

    return {
        "category": category,
        "risk_level": risk_level,
        "requires_approval": requires_approval,
        "summary": summary,
        "tools": clean_tools,
    }


def plan_with_deepseek(text: str, fallback: dict[str, Any]) -> dict[str, Any]:
    if not get_llm_status()["configured"]:
        return {"used": False, "intent": fallback, "error": "DEEPSEEK_API_KEY is not configured"}

    system = (
        "你是安全智能运维 Agent 的意图解析器。"
        "你只能输出 JSON，不输出 Markdown。"
        "不要生成 shell 命令，不要要求绕过安全审计。"
        "可用工具只有：get_system_overview, get_resource_usage, get_filesystem_usage, "
        "find_large_files, find_deleted_open_files, list_processes, sample_top_processes, find_zombie_processes, list_ports, query_journal, query_kernel_log, get_service_status。"
        "JSON 字段：category, risk_level, requires_approval, summary, tools。"
        "category 只能是 disk_diagnosis, process_diagnosis, network_port_diagnosis, "
        "log_diagnosis, service_status, resource_diagnosis, system_overview。risk_level 只能是 readonly, low, medium, high, forbidden。"
        "涉及删除、修改、重启、kill、chmod、chown、清理等动作时 requires_approval 必须为 true。"
    )
    user = f"用户运维请求：{text}"
    result = _post_chat([{"role": "system", "content": system}, {"role": "user", "content": user}], max_tokens=500)
    if not result["success"]:
        return {"used": False, "intent": fallback, "error": result["error"]}
    parsed = _extract_json(result["content"])
    if not parsed:
        return {"used": False, "intent": fallback, "error": "model did not return JSON", "content": result["content"][:300]}
    return {"used": True, "intent": _validate_plan(parsed, fallback), "raw_content": result["content"][:800]}


def _compact_tool_results(tool_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compact = []
    for result in tool_results:
        data = result.get("data") or {}
        item: dict[str, Any] = {
            "tool": result.get("tool"),
            "success": result.get("success"),
            "risk_level": result.get("risk_level"),
            "duration_ms": result.get("duration_ms"),
        }
        if isinstance(data, dict):
            if "count" in data:
                item["count"] = data.get("count")
            if "items" in data and isinstance(data["items"], list):
                item["items_sample"] = data["items"][:5]
            for key in ("cpu_percent", "memory", "swap", "host", "os", "arch"):
                if key in data:
                    item[key] = data[key]
        compact.append(item)
    return compact


def summarize_with_deepseek(
    *,
    user_text: str,
    intent: dict[str, Any],
    security: dict[str, Any],
    tool_results: list[dict[str, Any]],
    approval: dict[str, Any] | None,
    fallback_answer: str,
    knowledge_refs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not get_llm_status()["configured"]:
        return {"used": False, "answer": fallback_answer, "error": "DEEPSEEK_API_KEY is not configured"}
    if not security.get("allowed", False):
        return {"used": False, "answer": fallback_answer, "error": "blocked request is not sent to external LLM"}

    system = (
        "你是面向麒麟 Linux 的安全智能运维 Agent。"
        "根据结构化证据生成中文答复。回答必须简短，最多 6 行。"
        "格式固定为：结论、证据、建议、风险。"
        "不要寒暄，不要解释系统设计，不要编造未采集到的数据。"
        "不要输出可直接破坏系统的命令。涉及删除、重启、权限修改时只说需要审批。"
    )
    user_payload = {
        "user_request": user_text,
        "intent": intent,
        "security": {
            "risk_level": security.get("risk_level"),
            "action": security.get("action"),
            "matched_rules": security.get("matched_rules", []),
        },
        "tool_results": _compact_tool_results(tool_results),
        "knowledge_refs": [
            {
                "layer": item.get("layer_name") or item.get("layer"),
                "title": item.get("title"),
                "content": str(item.get("content") or "")[:400],
                "source": item.get("source_type"),
            }
            for item in (knowledge_refs or [])[:5]
        ],
        "approval": approval,
    }
    result = _post_chat(
        [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        max_tokens=320,
    )
    if not result["success"]:
        return {"used": False, "answer": fallback_answer, "error": result["error"]}
    answer = str(result["content"]).strip()
    return {"used": True, "answer": answer or fallback_answer}
