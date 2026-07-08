# 麒麟智维安全运维助手

麒麟智维安全运维助手是一套面向麒麟 Linux 环境的安全智能运维 Agent。系统通过自然语言对话理解运维意图，结合命令风险识别、最小权限执行、审批控制、审计追踪和知识库沉淀，帮助管理员完成可控、可追溯的日常运维。

## 核心能力

- 自然语言运维：将用户输入解析为结构化意图、风险等级和工具执行计划。
- 安全护栏：识别危险命令、提示词注入、服务启停、权限变更、关键路径写入等高风险行为。
- 最小权限执行：后端服务以 `ops-agent` 低权限账号运行，仅通过 sudoers 白名单调用必要系统工具。
- 审批闭环：高风险操作进入审批中心，审批通过后才会继续执行，重复审批、过期审批和参数变化都会被拒绝。
- Tool 管理：提供工具注册、启用、禁用、健康检查、版本展示和执行结果记录。
- 审计追踪：按 trace_id 串联用户请求、安全检查、AI 分析、知识库命中、Tool 执行、审批结果和最终反馈。
- 知识库 RAG：支持 Linux 知识、历史故障、运维规范和用户问答沉淀，回答时自动引用相关知识。
- 实时监控：展示 CPU、内存、网络、磁盘、端口、审批和风险状态，并提供趋势图。

## 目录结构

```text
a2-secops-agent/
  backend/
    app/
      main.py          # HTTP 服务入口
      agent.py         # Agent 编排与意图处理
      guardrail.py     # 风险规则与安全检查
      tools.py         # 受控 Tool 实现
      audit.py         # 审计写入与查询
      storage.py       # SQLite 数据存储
      knowledge.py     # 知识库检索与沉淀
  frontend/
    index.html         # Web 控制台
    app.js
    styles.css
  deploy/
    install_kylin.sh   # 麒麟环境安装脚本
    update_local.sh    # 已安装环境更新脚本
    run_demo_user.sh   # 普通用户运行脚本
    security_rules.json
    sudoers/
    systemd/
  tests/
    smoke_test.py
    performance_test.py
```

## 环境要求

- 麒麟 Linux 或兼容的 Linux 发行版
- Python 3
- bash、sudo、systemd
- 常用诊断工具：`ss`、`lsof`、`journalctl`、`dmesg`

系统使用 Python 标准库实现核心服务，无需安装额外 Python 依赖。

## 快速部署

将发布包解压到服务器后执行：

```bash
cd a2-secops-agent
sudo bash deploy/install_kylin.sh
```

安装脚本会完成以下操作：

- 创建 `ops-agent` 低权限运行账号
- 安装服务目录到 `/opt/a2-secops-agent`
- 创建配置目录 `/etc/a2-secops-agent`
- 安装安全规则库
- 安装 sudoers 白名单
- 安装并启动 systemd 服务

检查服务状态：

```bash
systemctl status a2-secops-agent --no-pager
curl http://127.0.0.1:8765/api/v1/health
```

访问控制台：

```text
http://服务器IP:8765
```

默认账号：

```text
admin    / a2admin123
operator / a2operator123
auditor  / a2auditor123
```

安全提示：上述账号用于比赛演示和首次启动。正式部署前请在环境文件中修改 `A2_ADMIN_PASSWORD`、`A2_OPERATOR_PASSWORD` 和 `A2_AUDITOR_PASSWORD`，或在安装前通过同名环境变量覆盖默认值。系统会对连续登录失败进行限流，并支持退出登录时撤销当前 Token。

示例：

```bash
sudo A2_ADMIN_PASSWORD='请替换为强密码' bash deploy/install_kylin.sh
sudo vi /etc/a2-secops-agent/a2-secops-agent.env
sudo systemctl restart a2-secops-agent
```

## 普通用户运行

如果当前环境不能创建系统账号、安装 systemd 服务或配置 sudoers，可以使用普通用户模式运行：

```bash
cd a2-secops-agent
bash deploy/run_demo_user.sh
```

普通用户模式可以使用对话、知识库、审计、审批和大部分只读诊断能力；涉及系统级权限的操作会受到当前用户权限限制。

## DeepSeek 配置

未配置外部模型时，系统会使用本地规则完成意图识别、风险判断和结果总结。配置 DeepSeek 后，Agent 会优先使用模型生成结构化计划和自然语言总结；如果模型调用失败，会自动回退到本地规则。

推荐在 `/etc/a2-secops-agent/a2-secops-agent.env` 中配置：

```bash
DEEPSEEK_API_KEY="your_api_key"
DEEPSEEK_BASE_URL="https://api.deepseek.com"
DEEPSEEK_MODEL="deepseek-v4-flash"
```

修改配置后重启服务：

```bash
sudo systemctl restart a2-secops-agent
```

查看模型状态：

```bash
curl http://127.0.0.1:8765/api/v1/llm/status
```

安全说明：被安全护栏拦截的危险请求不会发送给外部模型。

## RBAC 权限

```text
admin
  可使用对话运维、审批中心、审计追踪、Tool 管理和知识库。

operator
  可使用对话运维、知识库和只读 Tool 信息，不能审批或查看完整审计。

auditor
  可查看审计追踪、知识库和只读信息，不能执行运维对话。
```

## 安全执行机制

系统不会直接拼接 shell 命令执行用户输入。所有可执行动作都会经过以下流程：

```text
用户请求
  -> 意图识别
  -> 风险规则检查
  -> Tool 计划生成
  -> 权限与审批判断
  -> argv 数组方式执行受控 Tool
  -> 结果验证
  -> 审计写入
  -> 知识沉淀
  -> 返回结论
```

高风险行为包括但不限于：

- 删除根目录、系统目录或关键日志
- 修改 `/etc`、`/boot`、`/usr` 等关键路径
- 停止、重启或禁用关键服务
- 修改权限、属主、内核参数或防火墙规则
- 包管理安装、删除、升级
- kill 关键进程
- 提示词注入绕过安全策略

## 审批机制

当请求需要审批时，系统会生成审批单并记录：

- 审批 ID
- trace_id
- 操作工具
- 参数摘要
- 风险等级
- payload_hash
- 过期时间
- 审批状态

审批执行前会重新校验审批状态、过期时间和参数哈希。审批单只能处理一次，过期或参数变化后不会继续执行。

## 审计与导出

审计接口支持按以下条件过滤：

- trace_id
- 用户
- 主机
- 风险等级
- 事件类型
- Tool 名称
- 时间范围

支持导出：

```text
CSV
JSONL
```

完整链路查询：

```bash
curl http://127.0.0.1:8765/api/v1/audit/trace/<trace_id>
```

## 安全规则扩展

默认规则文件：

```text
/etc/a2-secops-agent/security_rules.json
```

也可以通过环境变量指定：

```bash
A2_RULES_FILE=/path/to/security_rules.json
```

修改规则后重启服务：

```bash
sudo systemctl restart a2-secops-agent
```

## 更新部署

服务已经安装后，使用新发布包更新：

```bash
cd a2-secops-agent
sudo bash deploy/update_local.sh
```

更新后检查：

```bash
systemctl status a2-secops-agent --no-pager
curl http://127.0.0.1:8765/api/v1/health
```

## 验证命令

```bash
python3 tests/smoke_test.py
python3 tests/performance_test.py
id ops-agent
sudo -l -U ops-agent
systemctl status a2-secops-agent --no-pager
```

## 常见问题

### 页面显示不全

低分辨率或浏览器缩放过大时，控制台可能出现横向显示不完整。可以将浏览器缩放调整到 80% 或使用全屏模式。

### 端口无法访问

确认服务已启动，并检查防火墙策略：

```bash
systemctl status a2-secops-agent --no-pager
ss -lntp | grep 8765
```

### DeepSeek 未连接

检查环境文件是否存在、API Key 是否正确，并重启服务：

```bash
cat /etc/a2-secops-agent/a2-secops-agent.env
sudo systemctl restart a2-secops-agent
curl http://127.0.0.1:8765/api/v1/llm/status
```
