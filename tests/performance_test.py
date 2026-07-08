from __future__ import annotations

import concurrent.futures
import json
import os
import statistics
import time
import urllib.request


BASE = os.environ.get("A2_BASE_URL", "http://127.0.0.1:8765")
USER = os.environ.get("A2_PERF_USER", "admin")
PASSWORD = os.environ.get("A2_PERF_PASSWORD", "a2admin123")


def request(path: str, payload: dict | None = None, token: str | None = None) -> tuple[float, dict]:
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    started = time.perf_counter()
    if payload is None:
        req = urllib.request.Request(BASE + path, headers=headers)
    else:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
        req = urllib.request.Request(BASE + path, data=body, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return (time.perf_counter() - started) * 1000, data


def percentile(values: list[float], pct: float) -> float:
    values = sorted(values)
    if not values:
        return 0.0
    idx = min(len(values) - 1, int(round((pct / 100) * (len(values) - 1))))
    return values[idx]


def summarize(name: str, values: list[float]) -> dict:
    return {
        "name": name,
        "count": len(values),
        "avg_ms": round(statistics.mean(values), 2) if values else 0,
        "p50_ms": round(percentile(values, 50), 2),
        "p95_ms": round(percentile(values, 95), 2),
        "max_ms": round(max(values), 2) if values else 0,
    }


def main() -> None:
    _, login = request("/api/v1/auth/login", {"username": USER, "password": PASSWORD})
    token = login["token"]

    guardrail_times = []
    for command in ["rm -rf /", "chmod -R 777 /etc", "systemctl restart sshd"] * 20:
        elapsed, _ = request("/api/v1/security/check-command", {"command": command}, token)
        guardrail_times.append(elapsed)

    def call_dashboard() -> float:
        elapsed, _ = request("/api/v1/dashboard", token=token)
        return elapsed

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        dashboard_times = list(pool.map(lambda _: call_dashboard(), range(20)))

    _, resources = request("/api/v1/dashboard", token=token)
    result = {
        "base_url": BASE,
        "targets": {
            "guardrail_p95_ms": "<100",
            "readonly_query_p95_ms": "<5000",
            "concurrent_sessions": ">=20",
            "backend_memory_mb": "<512",
        },
        "results": [
            summarize("guardrail_check", guardrail_times),
            summarize("dashboard_20_concurrent", dashboard_times),
        ],
        "resource_sample": {
            "cpu_percent": resources.get("resources", {}).get("cpu_percent"),
            "memory_percent": resources.get("resources", {}).get("memory", {}).get("percent"),
        },
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
