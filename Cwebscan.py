#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 合并并修复后的 C 段 web 应用信息扫描工具
# 作者: 合并自 lemonlove7 / se55i0n，已适配 Python3
from gevent import monkey as gevent_monkey
gevent_monkey.patch_all()

import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', category=SyntaxWarning)
warnings.filterwarnings('ignore', message='.*Monkey-patching ssl.*')

import argparse
import csv
import socket
import sys
import time
import threading
import queue
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing.dummy import Lock
import os

import IPy
import dns.resolver
import gevent
import requests
from bs4 import BeautifulSoup
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# 颜色
W = '\033[0m'
G = '\033[1;32m'
O = '\033[1;33m'
R = '\033[1;31m'

DEFAULT_PORTS = [80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10250,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,28018,20880]

class Scanner:
    def __init__(self, server, threads=50, custom_ports=None, filename_time=None, csv_lock=None):
        self.server = server.strip()
        self.threads = threads
        self.custom_ports = custom_ports
        self.ips = []
        self.start_time = time.time()
        self.lock = Lock()
        self.csv_lock = csv_lock or threading.Lock()
        self.filename_time = filename_time or time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())
        self.result_ips = []
        self.target_range = self.handle_target()
        self.get_ip_addr()

    def handle_target(self):
        # 如果是单个IP则返回该IP所在C段网段，否则尝试解析域名并返回C段
        try:
            last_octet = int(self.server.split('.')[-1])
            # 若解析为IP，构造C段网段
            return '.'.join(self.server.split('.')[:3]) + '.0/24'
        except Exception:
            # 可能为域名，先检测CDN再解析
            answers = self.check_cdn()
            if answers and len(answers) > 1:
                print(f'{O}[-] 目标解析到多个IP，将直接扫描这些IP：{", ".join(answers)}{W}')
                # 直接使用解析到的 IP 列表，跳过生成整个 C 段
                self.ips = answers
                return None
            try:
                resolved = socket.gethostbyname(self.server)
                return '.'.join(resolved.split('.')[:3]) + '.0/24'
            except Exception as e:
                print(f'{R}[-] 无法解析目标：{self.server} -> {e}{W}')
                return None

    def check_cdn(self):
            # 使用多个公共DNS解析获取 A 记录，返回解析到的唯一 IP 列表（用于处理 CDN 情况）
            resolvers = [['114.114.114.114'], ['8.8.8.8'], ['223.6.6.6']]
            answers = []
            r = dns.resolver.Resolver()
            r.lifetime = r.timeout = 2.0
            for nameserver in resolvers:
                try:
                    r.nameservers = nameserver
                    # 使用 resolver.resolve for dnspython >=2.0 else fallback
                    try:
                        ar = r.resolve(self.server, 'A')
                        for rr in ar:
                            answers.append(rr.address)
                    except AttributeError:
                        ar = r.query(self.server, 'A')
                        for rr in ar:
                            answers.append(rr.address)
                except Exception:
                    continue
            unique = list(dict.fromkeys(answers))
            return unique

    def get_ip_addr(self):
        # 将C段网段拆成IP列表
        if not self.target_range:
            return
        try:
            for ip in IPy.IP(self.target_range):
                self.ips.append(str(ip))
        except Exception as e:
            print(f'{R}[-] 生成 IP 列表失败: {e}{W}')

    def get_info(self, ip, port):
        # 对单个 ip:port 检查 http/https 返回状态、Server、Title 并写入 CSV
        schemes = ['http://', 'https://']
        for scheme in schemes:
            url = f'{scheme}{ip}:{port}'
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 11; Windows NT 6.3)'}
            try:
                resp = requests.get(url, timeout=10, headers=headers, verify=False, allow_redirects=True)
                serv = ''
                title = ''
                try:
                    serv = resp.headers.get('Server', '') .split()[0] if resp.headers.get('Server') else ''
                except Exception:
                    serv = resp.headers.get('Server', '') if resp.headers.get('Server') else ''
                try:
                    soup = BeautifulSoup(resp.content, 'lxml')
                    if soup.title and soup.title.string:
                        title = soup.title.string.strip()
                except Exception:
                    title = ''
                line = f'{G}[+] {url.ljust(28)}{str(resp.status_code).ljust(6)}{serv.ljust(24)}{title}{W}'
                # 使用线程安全锁打印并写CSV
                with self.lock:
                    print(line)
                # 写 CSV（不同线程间需要额外锁）
                with self.csv_lock:
                    with open(self.filename_time + '.csv', 'a', newline='', encoding='utf-8') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow([url, str(resp.status_code), serv, title])
                # 如果成功返回则不再尝试另一个 scheme（避免重复记录）
                return
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
        # 如果两个 scheme 都失败则忽略
        return

    def start(self, ip):
        # 对一个 IP 启动若干 gevent 任务来检查多个端口
        ports = []
        if self.custom_ports:
            # 支持像 "80,8080" 的字符串或直接传入 list
            if isinstance(self.custom_ports, str):
                ports = [p.strip() for p in self.custom_ports.split(',') if p.strip()]
            elif isinstance(self.custom_ports, (list, tuple)):
                ports = [str(p) for p in self.custom_ports]
        else:
            ports = [str(p) for p in DEFAULT_PORTS]

        gevs = []
        for port in ports:
            try:
                gevs.append(gevent.spawn(self.get_info, ip, port))
            except Exception:
                continue
        if gevs:
            try:
                gevent.joinall(gevs, timeout=15)
            except Exception:
                pass

    def run(self):
        if not self.ips:
            print(f'{O}[-] 没有可扫描的 IP: {self.server}{W}')
            return
        # 如果 CSV 文件不存在或为空，写入表头
        try:
            with self.csv_lock:
                try:
                    with open(self.filename_time + '.csv', 'r', encoding='utf-8') as f:
                        first = f.read(1)
                except FileNotFoundError:
                    with open(self.filename_time + '.csv', 'w', newline='', encoding='utf-8') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(['url', 'status', 'server', 'title'])
        except Exception:
            pass

        try:
            pool = ThreadPool(processes=self.threads)
            pool.map_async(self.start, self.ips).get(0xffff)
            pool.close()
            pool.join()
        except KeyboardInterrupt:
            print(f'\n{R}[-] 用户终止扫描...{W}')
            sys.exit(1)
        except Exception:
            pass
        finally:
            elapsed = time.time() - self.start_time
            print('-' * 90)
            print(f'{O}[-] 目标 {self.server} 扫描完成, 用时: {elapsed:.2f} 秒{W}')


def banner():
    b = r'''
   ______              __
  / ____/      _____  / /_  ______________ _____  ____  ___  _____
 / /   | | /| / / _ \/ __ \/ ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/   pro 
/ /___ | |/ |/ /  __/ /_/ (__  ) /__/ /_/ / / / / / /  __/ /       max
\____/ |__/|__/\___/_.___/____/\___/\__,_/_/ /_/_/ /_/\___/_/        ultra
    '''
    print('\033[1;34m' + b + '\033[0m')
    print('-' * 90)


def worker_thread(q, args, filename_time, csv_lock):
    while True:
        try:
            target = q.get_nowait()
        except queue.Empty:
            return
        if not target:
            q.task_done()
            continue
        scanner = Scanner(target, threads=args.t_inner, custom_ports=args.custom_ports, filename_time=filename_time, csv_lock=csv_lock)
        scanner.run()
        q.task_done()


def parse_args():
    parser = argparse.ArgumentParser(description='Example: python Cwebscan.py targets.txt -p8080,9090 -t 10')
    parser.add_argument('target', help='targets file: 每行 IP 或 域名 (将扫描其 C 段)',)
    parser.add_argument('-T', type=int, default=10, dest='threads', help='并发工作线程数（同时处理多少个目标文件的 Scanner），默认 10')
    parser.add_argument('-t', type=int, default=50, dest='t_inner', help='每个目标内部并发线程数（扫描 IP 列表时的线程池大小），默认 50')
    parser.add_argument('-p', dest='custom_ports', default=None, help='自定义扫描端口, 例如 "80,8080,443"')
    parser.add_argument('-o', dest='output', default=None, help='输出 CSV 文件基名（默认使用时间戳）')
    return parser.parse_args()


def main():
    banner()
    args = parse_args()
    filename_time = args.output or time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime())
    # 支持传入目标文件，也支持直接传入单个域名或逗号分隔的目标列表
    targets = []
    if os.path.isfile(args.target):
        try:
            with open(args.target, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        except Exception as e:
            print(f'{R}[-] 无法打开目标文件 {args.target} : {e}{W}')
            sys.exit(1)
    else:
        # 可能直接是域名或逗号分隔的多个目标
        if ',' in args.target:
            targets = [t.strip() for t in args.target.split(',') if t.strip()]
        else:
            targets = [args.target.strip()]

    if not targets:
        print(f'{R}[-] 目标文件中没有可用条目{W}')
        sys.exit(1)

    q = queue.Queue()
    for t in targets:
        q.put(t)

    csv_lock = threading.Lock()

    threads = []
    worker_count = max(1, args.threads)
    for i in range(worker_count):
        th = threading.Thread(target=worker_thread, args=(q, args, filename_time, csv_lock))
        th.daemon = True
        th.start()
        threads.append(th)

    try:
        # 等待队列处理完
        q.join()
    except KeyboardInterrupt:
        print(f'\n{R}[-] 用户终止主线程...{W}')
    finally:
        # 等待线程结束（短时间内）
        for th in threads:
            th.join(timeout=0.1)

    print(f'{O}[-] 全部任务完成, 输出文件: {filename_time}.csv{W}')


if __name__ == '__main__':
    main()