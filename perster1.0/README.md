# 终极渗透测试框架 - 全平台增强版

一款高级渗透测试框架，支持Windows、Linux、macOS、Android、iOS和HarmonyOS等多平台测试，集成了最新的漏洞利用技术和规避方法。

## 主要特性

- **多平台支持**：全面覆盖主流操作系统和设备
- **智能分析**：自动目标分析、威胁建模和攻击路径规划
- **最新漏洞利用**：集成2024年最新漏洞利用模块
- **高级规避技术**：5级逃逸技术对抗安全防护
- **自动化工作流**：从侦察到后渗透的完整自动化
- **专业报告**：生成详细的技术报告和修复建议

## 支持平台

| 平台      | 支持版本 | 专用模块 |
|-----------|----------|----------|
| Windows   | 7/10/11  | ✔️       |
| Linux     | 主流发行版 | ✔️     |
| macOS     | 10.15+   | ✔️       |
| Android   | 8.0+     | ✔️       |
| iOS       | 12.0+    | ✔️       |
| HarmonyOS | 2.0+     | ✔️       |
| Web应用   | 全平台   | ✔️       |

## 安装要求

### 基本要求
- Kali Linux 2023.x或更高版本
- Python 3.8+
- Root权限（部分功能需要）

### 依赖安装
```bash
sudo apt update && sudo apt install -y \
    metasploit-framework \
    nmap \
    sqlmap \
    nikto \
    gobuster \
    john \
    wafw00f \
    whatweb \
    nuclei \
    adb \
    apktool \
    apksigner \
    osslsigncode \
    upx \
    frida \
    objection
```
### 快速开始

## 基本用法
```bash
sudo python3 perster.py <目标IP或域名> [选项]
```
完整选项
| 选项	              |  描述              |
|---------------------|--------------------|
|-o DIR, --output DIR |	指定输出目录        |
|-ngrok-token TOKEN	  |设置Ngrok认证令牌    |
|--evasion LEVEL	  |设置逃逸级别(1-5)    |
|--proxy URL	      |设置代理服务器       |
|--stealth	          |启用隐身模式         |
|--no-progress	      |禁用进度显示         |
|--windows	          |强制启用Windows模块  |
|--linux	          |强制启用Linux模块    |
|--macos	          |强制启用macOS模块    |
|--web	              |强制启用Web模块      |
|--android	          |强制启用Android模块  |
|--ios	              |强制启用iOS模块      |
|--harmony	          |强制启用HarmonyOS模块|
|--full	              |执行完整测试         |

### 技术架构
```text
├── 侦察阶段
│   ├── 网络拓扑分析
│   ├── 服务指纹识别
│   └── 漏洞扫描
├── 漏洞利用
│   ├── 自动化漏洞验证
│   └── 多平台利用模块
├── 后渗透
│   ├── 权限维持
│   ├── 横向移动
│   └── 数据提取
└── 报告生成
    ├── 漏洞详情
    ├── 风险评级
    └── 修复建议
```
### 报告示例
## 框架生成的报告包含以下部分：

执行摘要 - 测试概览和关键发现

技术细节 - 所有发现的漏洞详情

利用证据 - 漏洞验证截图和输出

风险评级 - CVSS评分和业务影响

修复建议 - 详细的修复方案

## 报告格式支持：

Markdown (report.md)

HTML (report.html)

JSON (vulnerabilities.json)

### 注意事项
合法使用：仅用于授权测试，使用前必须获得书面许可

网络影响：部分扫描可能对目标系统造成负载

数据安全：测试结果包含敏感信息，需妥善保管

系统要求：建议在Kali Linux下运行以获得最佳兼容性
