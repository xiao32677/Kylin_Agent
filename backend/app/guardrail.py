from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


RISK_ORDER = {"readonly": 0, "low": 1, "medium": 2, "high": 3, "forbidden": 4}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    pattern: str
    risk_level: str
    action: str
    message: str


RULES = [
    Rule("prompt_ignore_rules", "提示词注入：忽略规则", r"忽略.*(规则|限制|安全|审计)|ignore .*rules?", "forbidden", "block", "检测到绕过安全规则的提示词注入意图"),
    Rule("prompt_bypass_audit", "提示词注入：绕过审计", r"不要.*(记录|审计)|bypass .*audit", "forbidden", "block", "检测到绕过审计链路的请求"),
    Rule("prompt_reveal_system", "提示词注入：泄露系统提示词", r"系统提示词|system prompt|developer message", "forbidden", "block", "检测到泄露内部策略的请求"),
    Rule("rm_root_recursive", "禁止递归删除根目录", r"\brm\s+-[^\n]*r[^\n]*f[^\n]*(\s+/|\s+/\*)", "forbidden", "block", "禁止递归删除系统关键路径"),
    Rule("rm_critical_path", "禁止删除关键目录", r"\brm\s+-[^\n]*(/etc|/boot|/usr|/bin|/sbin|/var/lib|/root)\b", "forbidden", "block", "目标路径属于受保护关键目录"),
    Rule("chmod_777", "危险权限放开", r"\bchmod\s+(-R\s+)?777\b", "high", "approval", "chmod 777 需要审批，关键路径直接拒绝"),
    Rule("chmod_recursive_critical_path", "禁止递归修改关键路径权限", r"\bchmod\s+-R[^\n]*(/etc|/boot|/usr|/bin|/sbin|/var/lib)", "forbidden", "block", "禁止递归修改关键路径权限"),
    Rule("chown_recursive_critical_path", "禁止递归修改关键路径属主", r"\bchown\s+-R[^\n]*(/etc|/boot|/usr|/bin|/sbin|/var/lib)", "forbidden", "block", "禁止递归修改关键路径属主"),
    Rule("curl_pipe_shell", "禁止下载后直接执行", r"\b(curl|wget)\b[^\n]*(\||-O-)[^\n]*(sh|bash)", "forbidden", "block", "禁止下载脚本后直接交给 shell 执行"),
    Rule("mkfs_disk", "禁止格式化磁盘", r"\bmkfs\.[a-z0-9]+\s+/dev/", "forbidden", "block", "禁止格式化磁盘设备"),
    Rule("dd_disk_overwrite", "禁止覆盖磁盘", r"\bdd\b[^\n]*of=/dev/", "forbidden", "block", "禁止直接覆盖磁盘设备"),
    Rule("read_sensitive_file", "禁止读取敏感文件", r"\b(cat|less|more|tail)\b[^\n]*(/etc/shadow|id_rsa|\.pem|\.key)", "forbidden", "block", "禁止读取密码、密钥等敏感文件"),
    Rule("shell_command_chain", "命令链需要复核", r"(\&\&|\|\||;|`|\$\()", "high", "review", "检测到命令拼接或替换，必须进入安全复核"),
]

BLOCKED_PATHS = ["/", "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var/lib", "/root"]
CONTROLLED_CLEAN_PATHS = ["/var/log", "/tmp", "/opt"]

COMMAND_RULES = [
    Rule("systemctl_mutation", "service mutation requires approval", r"\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|unmask)\b", "high", "approval", "service mutation must be approved"),
    Rule("kill_process", "process termination requires approval", r"\bkill(all)?\b\s+-?[0-9A-Za-z_-]+", "high", "approval", "process termination must be approved"),
    Rule("package_mutation", "package mutation requires approval", r"\b(apt|apt-get|yum|dnf|rpm)\b\s+(install|remove|erase|upgrade|update|localinstall)\b", "high", "approval", "package mutation must be approved"),
    Rule("sysctl_write", "kernel parameter mutation requires approval", r"\bsysctl\b[^\n]*=", "high", "approval", "kernel parameter mutation must be approved"),
    Rule("write_critical_config", "critical config write blocked", r"(>|tee\s+|sed\s+-i|echo\b[^\n]*>)\s*(/etc|/boot|/usr|/bin|/sbin|/var/lib)\b", "forbidden", "block", "critical config write is blocked"),
]


def _load_configured_rules() -> list[Rule]:
    rules_file = os.environ.get("A2_RULES_FILE", "").strip()
    if not rules_file:
        return []
    try:
        with open(rules_file, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []
    items = raw.get("rules", raw) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        return []
    loaded: list[Rule] = []
    for item in items:
        if not isinstance(item, dict) or item.get("enabled") is False:
            continue
        try:
            loaded.append(
                Rule(
                    str(item["rule_id"]),
                    str(item.get("name") or item["rule_id"]),
                    str(item["pattern"]),
                    str(item["risk_level"]),
                    str(item["action"]),
                    str(item.get("message") or item.get("name") or item["rule_id"]),
                )
            )
        except KeyError:
            continue
    return loaded


def active_rules() -> list[Rule]:
    return [*RULES, *COMMAND_RULES, *_load_configured_rules()]


def _max_risk(current: str, new: str) -> str:
    return new if RISK_ORDER[new] > RISK_ORDER[current] else current


def check_text(input_text: str, input_type: str = "natural_language") -> dict[str, Any]:
    matched: list[dict[str, str]] = []
    risk_level = "readonly"
    action = "allow"
    allowed = True
    for rule in active_rules():
        if re.search(rule.pattern, input_text, flags=re.IGNORECASE):
            matched.append(
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "risk_level": rule.risk_level,
                    "action": rule.action,
                    "message": rule.message,
                }
            )
            risk_level = _max_risk(risk_level, rule.risk_level)
            if rule.action == "block" or rule.risk_level == "forbidden":
                action = "block"
                allowed = False
            elif action != "block":
                action = "approval" if rule.action == "approval" else "review"

    error_code = None
    if not allowed:
        error_code = "SEC_PROMPT_INJECTION" if any(m["rule_id"].startswith("prompt_") for m in matched) else "SEC_COMMAND_BLOCKED"
    elif action in {"approval", "review"}:
        error_code = "SEC_APPROVAL_REQUIRED"
    return {
        "allowed": allowed,
        "risk_level": risk_level,
        "action": action,
        "matched_rules": matched,
        "error_code": error_code,
        "input_type": input_type,
    }


def is_unsupported_request(text: str) -> dict[str, Any]:
    config_write_patterns = [
        r"(修改|更改|编辑).*(配置|内核参数|系统参数|配置文件)",
        r"(安装|卸载|升级).*(软件|软件包|依赖|服务)",
        r"\b(apt|apt-get|yum|dnf|rpm)\b",
        r"\bsysctl\b.*=",
    ]
    service_mutation_patterns = [
        r"(启动|停止|重启|关闭).*(服务|进程|nginx|mysql|ssh|sshd)",
        r"\bsystemctl\s+(start|stop|restart|reload|enable|disable)\b",
        r"\bkill\b\s+-?\d*",
    ]

    if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in config_write_patterns):
        return {
            "unsupported": True,
            "category": "unsupported_config_change",
            "risk_level": "high",
            "requires_approval": True,
            "summary": "用户请求修改配置或软件包状态",
            "reason": "当前版本尚未开放配置修改、软件安装或系统参数变更能力。",
        }
    if any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in service_mutation_patterns):
        return {
            "unsupported": True,
            "category": "unsupported_service_mutation",
            "risk_level": "high",
            "requires_approval": True,
            "summary": "用户请求启动、停止或重启服务/进程",
            "reason": "当前版本尚未开放真实服务启停能力，只能提供只读诊断和审批演示。",
        }
    return {"unsupported": False}


def is_file_write_request(text: str) -> bool:
    patterns = [
        r"(创建|生成|新建).*(文件|txt|\.log|\.md|\.json)",
        r"(写入|保存|追加).*(文件|内容)",
        r"\becho\b.+>",
        r"\btouch\b\s+",
        r"create .*file",
        r"write .*file",
    ]
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def classify_intent(text: str) -> dict[str, Any]:
    lower = text.lower()
    if is_file_write_request(text):
        return {
            "category": "file_write",
            "risk_level": "medium",
            "requires_approval": True,
            "summary": "创建或写入受控文本文件",
            "tools": [],
        }
    known_service = any(name in lower for name in ("nginx", "mysql", "mariadb", "ssh", "sshd", "docker", "a2-secops-agent"))
    if ("服务" in text and ("状态" in text or "运行" in text or "异常" in text or "错误" in text)) or known_service or "systemctl status" in lower or "service status" in lower:
        return {
            "category": "service_status",
            "risk_level": "readonly",
            "requires_approval": False,
            "summary": "查询服务状态并定位异常日志线索",
            "tools": ["get_service_status"],
        }
    unsupported = is_unsupported_request(text)
    if unsupported["unsupported"]:
        return {
            "category": unsupported["category"],
            "risk_level": unsupported["risk_level"],
            "requires_approval": unsupported["requires_approval"],
            "summary": unsupported["summary"],
            "tools": [],
            "unsupported": True,
            "unsupported_reason": unsupported["reason"],
        }
    if any(token in text for token in ("CPU", "内存", "负载", "卡顿", "很高", "飙高")) or any(token in lower for token in ("cpu", "memory", "load", "oom")):
        category = "resource_diagnosis"
        tools = ["get_resource_usage", "sample_top_processes", "query_journal", "query_kernel_log"]
        summary = "自动分析 CPU、内存、负载、进程排行和系统日志，定位资源异常原因"
    elif any(token in text for token in ("磁盘", "空间", "垃圾", "清理", "大文件")) or "disk" in lower:
        category = "disk_diagnosis"
        tools = ["get_filesystem_usage", "find_large_files"]
        summary = "分析磁盘空间、目录占用和大文件，先给出安全清理建议"
    elif any(token in text for token in ("僵尸", "进程")) or "zombie" in lower or "process" in lower:
        category = "process_diagnosis"
        tools = ["list_processes", "find_zombie_processes"]
        summary = "分析进程状态和僵尸进程"
    elif "端口" in text or "port" in lower or re.search(r"\b\d{2,5}\b", text):
        category = "network_port_diagnosis"
        tools = ["list_ports"]
        summary = "分析网络监听端口和进程归属"
    elif "日志" in text or "错误" in text or "error" in lower or "journal" in lower:
        category = "log_diagnosis"
        tools = ["query_journal"]
        summary = "查询近期错误日志并聚合异常线索"
    else:
        category = "system_overview"
        tools = ["get_system_overview", "get_resource_usage"]
        summary = "查看系统概览和资源使用率"

    wants_mutation = any(token in text for token in ("删除", "清理", "修复", "处理", "释放", "关闭", "停止", "重启", "修改", "kill"))
    risk_level = "medium" if wants_mutation and category != "system_overview" else "readonly"
    requires_approval = wants_mutation
    return {
        "category": category,
        "risk_level": risk_level,
        "requires_approval": requires_approval,
        "summary": summary,
        "tools": tools,
    }


def check_path_policy(path: str, operation: str) -> dict[str, Any]:
    normalized = str(PurePosixPath(path.replace("\\", "/")))
    if operation in {"write", "delete", "chmod", "chown"}:
        for blocked in BLOCKED_PATHS:
            if blocked == "/":
                is_blocked = normalized == "/"
            else:
                is_blocked = normalized == blocked or normalized.startswith(blocked.rstrip("/") + "/")
            if is_blocked:
                return {
                    "allowed": False,
                    "risk_level": "forbidden",
                    "error_code": "SEC_PATH_BLOCKED",
                    "matched_rule": "protected_path",
                    "message": f"{normalized} 属于受保护路径",
                }
        if operation == "delete" and not any(normalized == p or normalized.startswith(p + "/") for p in CONTROLLED_CLEAN_PATHS):
            return {
                "allowed": False,
                "risk_level": "high",
                "error_code": "SEC_APPROVAL_REQUIRED",
                "matched_rule": "delete_outside_controlled_paths",
                "message": "删除动作只能在受控清理路径内进行，并且需要审批",
            }
    return {"allowed": True, "risk_level": "readonly", "error_code": None}


def payload_hash(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
