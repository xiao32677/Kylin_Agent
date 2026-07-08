# 麒麟虚拟机启动说明

本文档说明发布包上传到麒麟虚拟机后，如何解压、安装、启动并访问系统。

## 1. 打开终端

在麒麟桌面中打开终端，进入发布包所在目录。下面以 `~/Downloads` 为例：

```bash
cd ~/Downloads
```

如果发布包在其他目录，请先切换到对应目录。

## 2. 解压发布包

```bash
unzip a2-secops-agent-release-*.zip
cd a2-secops-agent
```

如果系统提示没有 `unzip`，可以在文件管理器中右键压缩包并选择解压。

## 3. 安装并启动服务

推荐使用正式服务模式：

```bash
sudo bash deploy/install_kylin.sh
```

脚本会自动完成：

- 创建 `ops-agent` 运行账号
- 安装服务文件
- 配置 sudoers 白名单
- 安装安全规则库
- 启动 `a2-secops-agent` 服务

## 4. 检查服务状态

```bash
systemctl status a2-secops-agent --no-pager
```

看到 `active (running)` 表示服务已经启动。

也可以检查健康接口：

```bash
curl http://127.0.0.1:8765/api/v1/health
```

正常会返回类似：

```json
{"status":"ok","service":"a2-secops-agent"}
```

## 5. 打开系统

在麒麟虚拟机浏览器中访问：

```text
http://127.0.0.1:8765
```

默认账号：

```text
admin    / a2admin123
operator / a2operator123
auditor  / a2auditor123
```

安全提示：默认账号仅用于比赛演示和首次启动。正式部署前请修改 `/etc/a2-secops-agent/a2-secops-agent.env` 中的 `A2_ADMIN_PASSWORD`、`A2_OPERATOR_PASSWORD` 和 `A2_AUDITOR_PASSWORD`，也可以在安装前通过同名环境变量覆盖。系统已对连续登录失败做限流，退出登录时会撤销当前 Token。

## 6. 配置 DeepSeek

如需接入 DeepSeek，编辑配置文件：

```bash
sudo vi /etc/a2-secops-agent/a2-secops-agent.env
```

写入以下内容：

```bash
DEEPSEEK_API_KEY="your_api_key"
DEEPSEEK_BASE_URL="https://api.deepseek.com"
DEEPSEEK_MODEL="deepseek-v4-flash"
```

保存后重启服务：

```bash
sudo systemctl restart a2-secops-agent
```

检查模型状态：

```bash
curl http://127.0.0.1:8765/api/v1/llm/status
```

## 7. 已安装后的再次启动

如果系统已经安装过，只需要启动服务：

```bash
sudo systemctl start a2-secops-agent
```

设置开机自启：

```bash
sudo systemctl enable a2-secops-agent
```

重启服务：

```bash
sudo systemctl restart a2-secops-agent
```

停止服务：

```bash
sudo systemctl stop a2-secops-agent
```

## 8. 普通用户运行方式

如果当前环境不能使用 sudo 或 systemd，可以用普通用户方式启动：

```bash
cd ~/Downloads/a2-secops-agent
bash deploy/run_demo_user.sh
```

然后在浏览器中访问：

```text
http://127.0.0.1:8765
```

普通用户方式可以使用 Web 控制台、登录鉴权、RBAC、自然语言意图识别、安全风险过滤、审批、审计、知识库和只读诊断能力。需要系统级权限的 Tool 会受到当前用户权限限制。

## 9. 常见问题

### 页面打不开

先检查服务是否运行：

```bash
systemctl status a2-secops-agent --no-pager
```

再检查端口是否监听：

```bash
ss -lntp | grep 8765
```

查看服务日志：

```bash
journalctl -u a2-secops-agent -n 100 --no-pager
```

### 页面显示不完整

将浏览器缩放调整到 80%，或把浏览器切换到全屏。

### 需要重新安装

进入解压后的项目目录重新执行：

```bash
sudo bash deploy/install_kylin.sh
```
