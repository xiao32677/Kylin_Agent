from __future__ import annotations

import json
import os
import platform
import re
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import psutil

from audit import now_iso
from guardrail import check_path_policy
from storage import DATA_DIR, connect


@dataclass
class Tool:
    name: str
    description: str
    risk_level: str
    permission: str
    requires_approval: bool
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], dict[str, Any]]
    timeout_ms: int = 30000

    def metadata(self, enabled: bool = True) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": "0.1.0",
            "description": self.description,
            "risk_level": self.risk_level,
            "permission": self.permission,
            "requires_approval": self.requires_approval,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "timeout_ms": self.timeout_ms,
            "enabled": enabled,
        }


def _run_argv(argv: list[str], timeout: int = 5, limit: int = 12000) -> dict[str, Any]:
    if not shutil.which(argv[0]):
        return {"success": False, "error": {"code": "COMPAT_COMMAND_MISSING", "message": f"{argv[0]} 不可用"}, "output": ""}
    try:
        proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, shell=False)
    except subprocess.TimeoutExpired:
        return {"success": False, "error": {"code": "TOOL_TIMEOUT", "message": "命令执行超时"}, "output": ""}
    output = (proc.stdout or proc.stderr or "")[:limit]
    return {
        "success": proc.returncode == 0,
        "error": None if proc.returncode == 0 else {"code": "TOOL_EXEC_FAILED", "message": f"返回码 {proc.returncode}"},
        "output": output,
    }


def _run_sudo_argv(argv: list[str], timeout: int = 5, limit: int = 12000) -> dict[str, Any]:
    command_path = shutil.which(argv[0])
    sudo_path = shutil.which("sudo")
    if not command_path:
        return {"success": False, "error": {"code": "COMPAT_COMMAND_MISSING", "message": f"{argv[0]} 不可用"}, "output": ""}
    if sudo_path and platform.system().lower() == "linux":
        result = _run_argv([sudo_path, "-n", command_path, *argv[1:]], timeout=timeout, limit=limit)
        if result["success"]:
            return result
    return _run_argv([command_path, *argv[1:]], timeout=timeout, limit=limit)


def ensure_tool_states() -> None:
    now = now_iso()
    with connect() as conn:
        for name in TOOLS:
            conn.execute(
                "INSERT OR IGNORE INTO tool_states (name, enabled, updated_at, updated_by) VALUES (?, 1, ?, ?)",
                (name, now, "system"),
            )


def _tool_enabled(name: str) -> bool:
    with connect() as conn:
        row = conn.execute("SELECT enabled FROM tool_states WHERE name = ?", (name,)).fetchone()
    return True if row is None else bool(row["enabled"])


def set_tool_enabled(name: str, enabled: bool, updated_by: str = "system") -> dict[str, Any]:
    if name not in TOOLS:
        return {"success": False, "error": {"code": "TOOL_NOT_FOUND", "message": "tool not found"}}
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO tool_states (name, enabled, updated_at, updated_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
              enabled = excluded.enabled,
              updated_at = excluded.updated_at,
              updated_by = excluded.updated_by
            """,
            (name, 1 if enabled else 0, now_iso(), updated_by),
        )
    return {"success": True, "name": name, "enabled": enabled}


def get_tool_health(name: str | None = None) -> dict[str, Any]:
    ensure_tool_states()
    names = [name] if name else list(TOOLS)
    items = []
    for tool_name in names:
        tool = TOOLS.get(tool_name)
        if not tool:
            items.append({"name": tool_name, "healthy": False, "error": {"code": "TOOL_NOT_FOUND", "message": "tool not found"}})
            continue
        enabled = _tool_enabled(tool_name)
        checks: list[dict[str, Any]] = []
        if tool_name in {"query_journal"}:
            checks.append({"command": "journalctl", "available": bool(shutil.which("journalctl"))})
        if tool_name in {"get_service_status"}:
            checks.append({"command": "systemctl", "available": bool(shutil.which("systemctl"))})
        if tool_name in {"find_deleted_open_files"}:
            checks.append({"command": "lsof", "available": bool(shutil.which("lsof"))})
        items.append({"name": tool_name, "enabled": enabled, "healthy": enabled and all(item["available"] for item in checks), "checks": checks})
    return {"items": items, "collected_at": now_iso()}


def get_system_overview(_: dict[str, Any]) -> dict[str, Any]:
    boot_time = psutil.boot_time()
    return {
        "host": platform.node(),
        "os": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "kernel": platform.version(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": psutil.cpu_count(logical=True),
        "boot_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(boot_time)),
        "uptime_seconds": int(time.time() - boot_time),
        "collected_at": now_iso(),
    }


def get_resource_usage(_: dict[str, Any]) -> dict[str, Any]:
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    net = psutil.net_io_counters()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "memory": {"total": vm.total, "used": vm.used, "available": vm.available, "percent": vm.percent},
        "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
        "network": {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
            "errin": net.errin,
            "errout": net.errout,
            "dropin": net.dropin,
            "dropout": net.dropout,
        },
        "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
        "collected_at": now_iso(),
    }


def get_filesystem_usage(_: dict[str, Any]) -> dict[str, Any]:
    items = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        items.append(
            {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
                "risk": "high" if usage.percent >= 90 else "medium" if usage.percent >= 80 else "normal",
            }
        )
    return {"items": items, "collected_at": now_iso()}


def list_processes(args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 20))
    items = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "username", "status", "memory_percent", "cpu_percent", "cmdline"]):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        items.append(
            {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "status": info.get("status"),
                "cpu_percent": round(float(info.get("cpu_percent") or 0), 2),
                "memory_percent": round(float(info.get("memory_percent") or 0), 2),
                "cmdline": " ".join(info.get("cmdline") or [])[:240],
            }
        )
    items.sort(key=lambda item: (item["memory_percent"], item["cpu_percent"]), reverse=True)
    return {"items": items[:limit], "count": len(items), "collected_at": now_iso()}


def sample_top_processes(args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 8))
    interval = float(args.get("interval", 0.2))
    if platform.system().lower() == "windows":
        ps = (
            "Get-Process | Sort-Object CPU -Descending | Select-Object -First "
            f"{max(1, min(limit, 50))} Id,ProcessName,CPU,PM | ConvertTo-Json -Compress"
        )
        result = _run_argv(["powershell", "-NoProfile", "-Command", ps], timeout=3, limit=20000)
        items = []
        if result["success"] and result["output"].strip():
            try:
                raw = json.loads(result["output"])
                rows = raw if isinstance(raw, list) else [raw]
            except json.JSONDecodeError:
                rows = []
            for row in rows:
                cpu_seconds = float(row.get("CPU") or 0)
                items.append(
                    {
                        "pid": row.get("Id"),
                        "ppid": None,
                        "name": row.get("ProcessName"),
                        "username": None,
                        "cpu_percent": 0,
                        "raw_cpu_percent": 0,
                        "cpu_seconds": round(cpu_seconds, 2),
                        "memory_percent": 0,
                        "memory_bytes": int(row.get("PM") or 0),
                        "cmdline": "",
                    }
                )
        return {"items": items, "count": len(items), "sample_interval_seconds": 0, "source": "powershell_get_process", "collected_at": now_iso()}

    attrs = ["pid", "ppid", "name", "memory_percent", "cpu_times"]
    first: dict[int, float] = {}
    for proc in psutil.process_iter(attrs):
        try:
            times = proc.info.get("cpu_times")
            first[int(proc.info["pid"])] = float(getattr(times, "user", 0.0) + getattr(times, "system", 0.0))
        except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError, TypeError, ValueError):
            continue
    time.sleep(max(0.1, min(interval, 2.0)))

    items = []
    cpu_count = psutil.cpu_count() or 1
    elapsed = max(interval, 0.1)
    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
            pid = int(info["pid"])
            times = info.get("cpu_times")
            total_time = float(getattr(times, "user", 0.0) + getattr(times, "system", 0.0))
            previous = first.get(pid, total_time)
            raw_cpu = max(0.0, (total_time - previous) / elapsed * 100.0)
            items.append(
                {
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "username": None,
                    "cpu_percent": round(raw_cpu / cpu_count, 2),
                    "raw_cpu_percent": round(raw_cpu, 2),
                    "memory_percent": round(float(info.get("memory_percent") or 0), 2),
                    "cmdline": "",
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError, TypeError, ValueError):
            continue
    items.sort(key=lambda item: (item["cpu_percent"], item["memory_percent"]), reverse=True)
    return {"items": items[:limit], "count": len(items), "sample_interval_seconds": interval, "collected_at": now_iso()}


def find_zombie_processes(_: dict[str, Any]) -> dict[str, Any]:
    zombies = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "username", "status"]):
        try:
            if proc.info.get("status") == psutil.STATUS_ZOMBIE:
                zombies.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {
        "items": zombies,
        "count": len(zombies),
        "recommendation": "若存在僵尸进程，应定位父进程并评估是否重启所属服务；核心服务必须审批后执行。",
        "collected_at": now_iso(),
    }


def list_ports(args: dict[str, Any]) -> dict[str, Any]:
    target_port = args.get("port")
    items = []
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        connections = []
    for conn in connections:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        port = conn.laddr.port
        if target_port and int(target_port) != port:
            continue
        process_name = None
        username = None
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                process_name = proc.name()
                username = proc.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        items.append(
            {
                "ip": conn.laddr.ip,
                "port": port,
                "pid": conn.pid,
                "process": process_name,
                "username": username,
                "status": conn.status,
            }
        )
    items.sort(key=lambda item: item["port"])
    return {"items": items, "count": len(items), "collected_at": now_iso()}


def release_port_guarded(args: dict[str, Any]) -> dict[str, Any]:
    approval_id = str(args.get("approval_id") or "").strip()
    if not approval_id:
        return {"released": False, "error": {"code": "SEC_APPROVAL_REQUIRED", "message": "释放端口需要审批 ID"}}
    try:
        port = int(args.get("port"))
    except (TypeError, ValueError):
        return {"released": False, "error": {"code": "REQ_SCHEMA_INVALID", "message": "port 必须是 1-65535 的整数"}}
    if port < 1 or port > 65535:
        return {"released": False, "error": {"code": "REQ_SCHEMA_INVALID", "message": "port 必须是 1-65535 的整数"}}
    if port == int(os.environ.get("A2_PORT", "8765")):
        return {"released": False, "error": {"code": "SEC_SELF_PROTECTION", "message": "禁止释放 Agent 自身服务端口"}}

    expected_pid = args.get("pid")
    expected_process = str(args.get("process") or "").strip()
    matches = list_ports({"port": port}).get("items", [])
    if not matches:
        return {"released": True, "already_free": True, "port": port, "message": "端口当前未被占用，无需处理"}

    target = matches[0]
    pid = target.get("pid")
    if not pid:
        return {"released": False, "port": port, "current": target, "error": {"code": "SEC_PID_UNKNOWN", "message": "无法确认占用端口的 PID，拒绝执行"}}
    if expected_pid and int(expected_pid) != int(pid):
        return {
            "released": False,
            "port": port,
            "current": target,
            "error": {"code": "SEC_TARGET_CHANGED", "message": "端口占用进程已变化，请重新诊断后再审批"},
        }

    try:
        proc = psutil.Process(int(pid))
        proc_name = proc.name()
        username = proc.username()
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        return {"released": False, "port": port, "error": {"code": "TOOL_EXEC_FAILED", "message": str(exc)}}

    protected_names = {"systemd", "init", "sshd", "dbus-daemon", "NetworkManager"}
    if int(pid) <= 1 or int(pid) == os.getpid() or proc_name in protected_names:
        return {
            "released": False,
            "port": port,
            "pid": pid,
            "process": proc_name,
            "error": {"code": "SEC_PROCESS_PROTECTED", "message": "目标进程属于保护范围，拒绝自动释放"},
        }
    if expected_process and expected_process != proc_name:
        return {
            "released": False,
            "port": port,
            "pid": pid,
            "process": proc_name,
            "error": {"code": "SEC_TARGET_CHANGED", "message": "进程名已变化，请重新诊断后再审批"},
        }

    proc.send_signal(signal.SIGTERM)
    gone, alive = psutil.wait_procs([proc], timeout=3)
    after = list_ports({"port": port}).get("items", [])
    released = not after
    return {
        "released": released,
        "port": port,
        "pid": pid,
        "process": proc_name,
        "username": username,
        "signal": "SIGTERM",
        "verification": {"port_free": released, "remaining": after, "process_exited": bool(gone) and not alive},
        "message": "端口已释放" if released else "已发送 SIGTERM，但端口仍被占用，请人工复核",
    }


def query_journal(args: dict[str, Any]) -> dict[str, Any]:
    lines = int(args.get("lines", 80))
    unit = str(args.get("unit") or "").strip()
    if platform.system().lower() == "linux":
        argv = ["journalctl", "-p", "warning..alert", "-n", str(lines), "--no-pager"]
        if unit:
            argv = ["journalctl", "-u", unit, "-p", "debug..alert", "-n", str(lines), "--no-pager"]
        result = _run_sudo_argv(argv, timeout=5)
        if result["success"]:
            output_lines = [line for line in result["output"].splitlines() if line.strip()]
            return {"items": output_lines[-lines:], "source": "journalctl", "unit": unit or None, "collected_at": now_iso()}
        return {"items": [], "source": "journalctl", "unit": unit or None, "warning": result["error"], "collected_at": now_iso()}

    return {
        "items": [
            "当前演示环境不是 Linux，未调用 journalctl。",
            "部署到麒麟高级服务器版 V11 后，该 Tool 将使用 journalctl 采集 warning..alert 日志。",
        ],
        "source": "compatibility_fallback",
        "unit": unit or None,
        "collected_at": now_iso(),
    }


def query_kernel_log(args: dict[str, Any]) -> dict[str, Any]:
    lines = int(args.get("lines", 80))
    if platform.system().lower() != "linux":
        return {"items": [], "source": "compatibility_fallback", "collected_at": now_iso()}
    result = _run_sudo_argv(["dmesg", "-T", "--level=err,warn,crit,alert,emerg"], timeout=5, limit=20000)
    if result["success"]:
        output_lines = [line for line in result["output"].splitlines() if line.strip()]
        return {"items": output_lines[-lines:], "source": "dmesg", "collected_at": now_iso()}
    fallback = _run_sudo_argv(["journalctl", "-k", "-p", "warning..alert", "-n", str(lines), "--no-pager"], timeout=5, limit=20000)
    output_lines = [line for line in fallback["output"].splitlines() if line.strip()]
    return {
        "items": output_lines[-lines:],
        "source": "journalctl -k",
        "warning": None if fallback["success"] else fallback["error"],
        "collected_at": now_iso(),
    }


def get_service_status(args: dict[str, Any]) -> dict[str, Any]:
    service = str(args.get("service") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,80}", service):
        return {"error": {"code": "REQ_SCHEMA_INVALID", "message": "service 名称不合法"}}
    if platform.system().lower() != "linux":
        return {"service": service, "source": "compatibility_fallback", "status": "仅 Linux/systemd 环境支持"}
    result = _run_sudo_argv(["systemctl", "status", service, "--no-pager"], timeout=5, limit=16000)
    lines = [line for line in result["output"].splitlines() if line.strip()]
    return {
        "service": service,
        "success": result["success"],
        "lines": lines[:120],
        "error": result["error"],
        "source": "systemctl",
        "collected_at": now_iso(),
    }


def _default_scan_paths() -> list[str]:
    if platform.system().lower() == "windows":
        return [os.environ.get("TEMP", str(Path.cwd()))]
    return ["/var/log", "/tmp", "/opt"]


def find_large_files(args: dict[str, Any]) -> dict[str, Any]:
    paths = args.get("paths") or _default_scan_paths()
    min_size_mb = int(args.get("min_size_mb", 50))
    limit = int(args.get("limit", 20))
    max_depth = int(args.get("max_depth", 4))
    threshold = min_size_mb * 1024 * 1024
    items = []
    for root in paths:
        root_path = Path(str(root)).expanduser()
        if not root_path.exists():
            continue
        base_depth = len(root_path.parts)
        for current_root, dirs, files in os.walk(root_path):
            current_path = Path(current_root)
            if len(current_path.parts) - base_depth >= max_depth:
                dirs[:] = []
            for filename in files:
                path = current_path / filename
                try:
                    stat = path.stat()
                except (OSError, PermissionError):
                    continue
                if stat.st_size >= threshold:
                    items.append(
                        {
                            "path": str(path),
                            "size_mb": round(stat.st_size / 1024 / 1024, 2),
                            "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                            "cleanup_policy": check_path_policy(str(path).replace("\\", "/"), "delete"),
                        }
                    )
            if len(items) >= limit * 3:
                break
    items.sort(key=lambda item: item["size_mb"], reverse=True)
    return {"items": items[:limit], "count": len(items), "collected_at": now_iso()}


def find_deleted_open_files(args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit", 20))
    if platform.system().lower() != "linux":
        return {
            "items": [],
            "count": 0,
            "source": "compatibility_fallback",
            "message": "open deleted file detection requires Linux lsof",
            "collected_at": now_iso(),
        }
    result = _run_sudo_argv(["lsof", "-nP", "+L1"], timeout=8, limit=24000)
    if not result["success"]:
        return {"items": [], "count": 0, "source": "lsof", "warning": result["error"], "collected_at": now_iso()}
    items = []
    for line in result["output"].splitlines()[1:]:
        if not line.strip() or "deleted" not in line.lower():
            continue
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        size = 0
        try:
            size = int(parts[6])
        except ValueError:
            pass
        items.append(
            {
                "command": parts[0],
                "pid": parts[1],
                "user": parts[2],
                "fd": parts[3],
                "type": parts[4],
                "size_bytes": size,
                "name": parts[8],
                "recommendation": "restart or reload the owning service after approval if the file is still consuming disk space",
            }
        )
        if len(items) >= limit:
            break
    return {"items": items, "count": len(items), "source": "lsof +L1", "collected_at": now_iso()}


def delete_file_guarded(args: dict[str, Any]) -> dict[str, Any]:
    path = str(args.get("path", ""))
    dry_run = bool(args.get("dry_run", True))
    policy = check_path_policy(path, "delete")
    if not policy["allowed"]:
        return {"deleted": False, "policy": policy}
    if dry_run:
        return {"deleted": False, "dry_run": True, "policy": policy, "message": "dry-run 通过，真实删除必须携带有效审批 ID"}
    return {"deleted": False, "message": "原型版本不执行真实删除，建议使用隔离目录移动策略", "policy": policy}


def write_text_file_guarded(args: dict[str, Any]) -> dict[str, Any]:
    filename = str(args.get("filename") or args.get("path") or "").strip()
    content = str(args.get("content") or "")
    approval_id = str(args.get("approval_id") or "").strip()
    if not approval_id:
        return {"written": False, "error": {"code": "SEC_APPROVAL_REQUIRED", "message": "写文件需要审批 ID"}}
    if not filename:
        return {"written": False, "error": {"code": "REQ_SCHEMA_INVALID", "message": "filename 不能为空"}}
    if len(content.encode("utf-8")) > 64 * 1024:
        return {"written": False, "error": {"code": "REQ_SCHEMA_INVALID", "message": "内容超过 64KB 限制"}}

    # Relative names are written into an Agent-managed directory, not the caller's cwd.
    if Path(filename).is_absolute():
        target = Path(filename)
        policy = check_path_policy(str(target).replace("\\", "/"), "write")
        if not policy["allowed"]:
            return {"written": False, "policy": policy}
    else:
        safe_name = Path(filename).name
        if safe_name != filename or safe_name in {"", ".", ".."}:
            return {"written": False, "error": {"code": "SEC_PATH_BLOCKED", "message": "只允许简单文件名或受控绝对路径"}}
        target = DATA_DIR / "managed_files" / safe_name
        policy = {"allowed": True, "risk_level": "medium", "target_scope": "agent_managed_dir"}

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {
        "written": True,
        "path": str(target),
        "bytes": len(content.encode("utf-8")),
        "policy": policy,
        "message": "文件已在审批通过后写入",
    }


TOOLS: dict[str, Tool] = {
    "get_system_overview": Tool(
        "get_system_overview",
        "获取 OS、内核、架构、运行时间和主机摘要",
        "readonly",
        "ops_readonly",
        False,
        {},
        {"type": "object"},
        get_system_overview,
    ),
    "get_resource_usage": Tool(
        "get_resource_usage",
        "获取 CPU、内存、Swap 和负载指标",
        "readonly",
        "ops_readonly",
        False,
        {},
        {"type": "object"},
        get_resource_usage,
    ),
    "get_filesystem_usage": Tool(
        "get_filesystem_usage",
        "获取文件系统和挂载点使用率",
        "readonly",
        "ops_readonly",
        False,
        {},
        {"type": "object"},
        get_filesystem_usage,
    ),
    "find_large_files": Tool(
        "find_large_files",
        "在受控目录内查找大文件并返回清理策略",
        "readonly",
        "ops_readonly",
        False,
        {"paths": "string[]", "min_size_mb": "integer", "max_depth": "integer", "limit": "integer"},
        {"type": "object"},
        find_large_files,
    ),
    "list_processes": Tool(
        "list_processes",
        "查询进程列表、父进程、资源占用和状态",
        "readonly",
        "ops_readonly",
        False,
        {"limit": "integer"},
        {"type": "object"},
        list_processes,
    ),
    "sample_top_processes": Tool(
        "sample_top_processes",
        "连续采样 CPU/内存占用最高的进程，用于资源异常根因分析",
        "readonly",
        "ops_readonly",
        False,
        {"limit": "integer", "interval": "number"},
        {"type": "object"},
        sample_top_processes,
    ),
    "find_zombie_processes": Tool(
        "find_zombie_processes",
        "识别 Z 状态僵尸进程并给出处理建议",
        "readonly",
        "ops_readonly",
        False,
        {},
        {"type": "object"},
        find_zombie_processes,
    ),
    "list_ports": Tool(
        "list_ports",
        "查询监听端口、进程和用户归属",
        "readonly",
        "ops_readonly",
        False,
        {"port": "integer"},
        {"type": "object"},
        list_ports,
    ),
    "release_port_guarded": Tool(
        "release_port_guarded",
        "审批后受控释放被进程占用的监听端口，并在执行后验证端口状态",
        "high",
        "ops_approval_required",
        True,
        {"port": "integer", "pid": "integer", "process": "string", "approval_id": "string"},
        {"type": "object"},
        release_port_guarded,
    ),
    "query_journal": Tool(
        "query_journal",
        "查询 systemd journal 近期告警和错误日志",
        "readonly",
        "ops_readonly",
        False,
        {"lines": "integer", "unit": "string"},
        {"type": "object"},
        query_journal,
    ),
    "query_kernel_log": Tool(
        "query_kernel_log",
        "查询内核 warning/error 日志，用于 CPU、驱动、OOM、硬件异常排查",
        "readonly",
        "ops_readonly_sudo_whitelist",
        False,
        {"lines": "integer"},
        {"type": "object"},
        query_kernel_log,
    ),
    "find_deleted_open_files": Tool(
        "find_deleted_open_files",
        "find files deleted on disk but still held open by processes",
        "readonly",
        "ops_readonly",
        False,
        {"limit": "integer"},
        {"type": "object"},
        find_deleted_open_files,
    ),
    "get_service_status": Tool(
        "get_service_status",
        "通过 systemctl status 查询单个服务状态",
        "readonly",
        "ops_readonly_sudo_whitelist",
        False,
        {"service": "string"},
        {"type": "object"},
        get_service_status,
    ),
    "delete_file_guarded": Tool(
        "delete_file_guarded",
        "受控删除文件；必须通过路径策略、安全校验和审批",
        "high",
        "ops_approval_required",
        True,
        {"path": "string", "reason": "string", "approval_id": "string", "dry_run": "boolean"},
        {"type": "object"},
        delete_file_guarded,
    ),
    "write_text_file_guarded": Tool(
        "write_text_file_guarded",
        "审批后在受控目录写入文本文件",
        "medium",
        "ops_approval_required",
        True,
        {"filename": "string", "content": "string", "approval_id": "string"},
        {"type": "object"},
        write_text_file_guarded,
    ),
}


def list_tool_metadata() -> list[dict[str, Any]]:
    ensure_tool_states()
    return [tool.metadata(enabled=_tool_enabled(name)) for name, tool in TOOLS.items()]


def invoke_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    tool = TOOLS.get(name)
    if not tool:
        return {"success": False, "error": {"code": "TOOL_NOT_FOUND", "message": f"{name} 未注册"}, "data": None}
    if not _tool_enabled(name):
        return {
            "tool": name,
            "success": False,
            "data": None,
            "error": {"code": "TOOL_DISABLED", "message": "tool is disabled"},
            "duration_ms": 0,
            "executed_by": "ops-agent",
            "risk_level": tool.risk_level,
        }
    started = time.perf_counter()
    try:
        data = tool.handler(arguments)
        policy = data.get("policy") if isinstance(data, dict) else None
        embedded_error = data.get("error") if isinstance(data, dict) else None
        success = not embedded_error and not (isinstance(policy, dict) and policy.get("allowed") is False)
        error = embedded_error
        if not error and isinstance(policy, dict) and policy.get("allowed") is False:
            error = {"code": policy.get("error_code", "SEC_PATH_BLOCKED"), "message": policy.get("message", "路径策略拒绝")}
    except Exception as exc:  # Tool failure must not crash Agent service.
        data = None
        success = False
        error = {"code": "TOOL_EXEC_FAILED", "message": str(exc)}
    return {
        "tool": name,
        "success": success,
        "data": data,
        "error": error,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "executed_by": "ops-agent",
        "risk_level": tool.risk_level,
    }
