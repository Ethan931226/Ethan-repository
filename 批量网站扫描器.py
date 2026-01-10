import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import threading
import queue
from urllib.parse import urlparse, urlunparse
from datetime import datetime
import json
import re


class BatchHttpScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("批量HTTP请求扫描器")
        try:
            self.root.geometry("1100x700")
        except Exception:
            pass

        # 状态与数据
        self.requests_queue = queue.Queue()
        self.scanning = False
        self.threads = []
        self.results = []

        # 变量占位（将在 create_widgets 中初始化）
        self.targets_text = None
        self.raw_request_text = None
        self.default_scheme = tk.StringVar(value='http')
        self.default_port_var = tk.StringVar(value='')
        self.default_suffix_var = tk.StringVar(value='/')
        self.method_var = tk.StringVar(value='GET')
        self.timeout_var = tk.StringVar(value='10')
        self.threads_var = tk.StringVar(value='6')
        self.extract_ip_var = tk.BooleanVar(value=True)

        # 创建界面
        self.create_widgets()

    def create_results_table(self, parent):
        columns = ('target','status','title','banner','content_length','time')
        self.results_tree = ttk.Treeview(parent, columns=columns, show='headings')
        for c, label in zip(columns, ['目标','状态','标题','服务器信息','内容长度','响应时间']):
            self.results_tree.heading(c, text=label)

        self.results_tree.column('target', width=360)
        self.results_tree.column('status', width=80)
        self.results_tree.column('title', width=200)
        self.results_tree.column('banner', width=180)
        self.results_tree.column('content_length', width=100)
        self.results_tree.column('time', width=120)

        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=vsb.set)
        self.results_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        vsb.pack(fill=tk.Y, side=tk.RIGHT)

        # 标签样式
        self.results_tree.tag_configure('success', background='#e8f5e9')
        self.results_tree.tag_configure('redirect', background='#fff3e0')
        self.results_tree.tag_configure('client_error', background='#ffebee')
        self.results_tree.tag_configure('server_error', background='#fce4ec')
        self.results_tree.tag_configure('error', background='#f5f5f5', foreground='#999')

        # 绑定事件
        self.results_tree.bind('<Double-1>', self.show_result_details)
        self.results_tree.bind('<<TreeviewSelect>>', self.on_result_select)
 
    def create_widgets(self):
        # 简化并保证所需控件存在
        main = ttk.Frame(self.root, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(main)
        header.pack(fill=tk.X)
        ttk.Label(header, text='批量HTTP请求扫描器', font=('Segoe UI', 14, 'bold')).pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value='就绪')
        ttk.Label(header, textvariable=self.status_var, foreground='#555').pack(side=tk.RIGHT)

        paned = ttk.Panedwindow(main, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        left = ttk.Frame(paned, width=380)
        paned.add(left, weight=0)

        tgt_frame = ttk.LabelFrame(left, text='目标与导入', padding=8)
        tgt_frame.pack(fill=tk.BOTH, expand=True, padx=(0,8), pady=(0,8))
        ttk.Label(tgt_frame, text='目标URL 或 主机 (每行一个)').pack(anchor=tk.W)
        self.targets_text = scrolledtext.ScrolledText(tgt_frame, height=12, font=('Consolas', 10))
        self.targets_text.pack(fill=tk.BOTH, expand=True, pady=(6,6))

        btns = ttk.Frame(tgt_frame)
        btns.pack(fill=tk.X)
        ttk.Button(btns, text='导入文件', command=self.import_targets).pack(side=tk.LEFT)
        ttk.Button(btns, text='从剪贴板粘贴', command=self.paste_from_clipboard).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='清空', command=self.clear_targets).pack(side=tk.RIGHT)

        cfg_frame = ttk.LabelFrame(left, text='请求配置', padding=8)
        cfg_frame.pack(fill=tk.X)

        row1 = ttk.Frame(cfg_frame)
        row1.pack(fill=tk.X)
        ttk.Label(row1, text='方法:').grid(row=0, column=0, sticky=tk.W)
        ttk.Combobox(row1, textvariable=self.method_var, values=['GET','POST','HEAD','PUT','DELETE'], width=8, state='readonly').grid(row=0, column=1, padx=6)
        ttk.Label(row1, text='超时(s):').grid(row=0, column=2, sticky=tk.W, padx=(10,0))
        ttk.Entry(row1, textvariable=self.timeout_var, width=6).grid(row=0, column=3, padx=6)
        ttk.Label(row1, text='线程:').grid(row=0, column=4, sticky=tk.W, padx=(10,0))
        ttk.Entry(row1, textvariable=self.threads_var, width=4).grid(row=0, column=5, padx=6)

        row2 = ttk.Frame(cfg_frame)
        row2.pack(fill=tk.X, pady=(8,0))
        ttk.Checkbutton(row2, text='自动提取IP/域名', variable=self.extract_ip_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Label(row2, text='协议:').grid(row=0, column=1, padx=(8,2))
        ttk.Combobox(row2, textvariable=self.default_scheme, values=['http','https'], width=6, state='readonly').grid(row=0, column=2)
        ttk.Label(row2, text='端口:').grid(row=0, column=3, padx=(8,2))
        ttk.Entry(row2, textvariable=self.default_port_var, width=6).grid(row=0, column=4)
        ttk.Label(row2, text='后缀:').grid(row=1, column=0, sticky=tk.W, pady=(6,0))
        ttk.Entry(row2, textvariable=self.default_suffix_var).grid(row=1, column=1, columnspan=4, sticky=tk.W+tk.E, pady=(6,0))

        ttk.Label(cfg_frame, text='原始请求模板 (可选，包含请求行/头/空行/体)：').pack(anchor=tk.W, pady=(8,2))
        self.raw_request_text = scrolledtext.ScrolledText(cfg_frame, height=8, font=('Consolas', 10))
        self.raw_request_text.pack(fill=tk.BOTH, expand=True)

        right = ttk.Frame(paned)
        paned.add(right, weight=1)

        vpaned = ttk.Panedwindow(right, orient=tk.VERTICAL)
        vpaned.pack(fill=tk.BOTH, expand=True)

        results_box = ttk.LabelFrame(vpaned, text='扫描结果', padding=6)
        vpaned.add(results_box, weight=1)

        preview_box = ttk.LabelFrame(vpaned, text='响应预览', padding=6)
        vpaned.add(preview_box, weight=0)

        self.create_results_table(results_box)

        self.preview_text = scrolledtext.ScrolledText(preview_box, height=12, font=('Consolas', 10))
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        self.preview_text.configure(state='disabled')

        bottom = ttk.Frame(main)
        bottom.pack(fill=tk.X, pady=(8,0))
        ttk.Button(bottom, text='开始扫描', command=self.start_scan).pack(side=tk.LEFT)
        ttk.Button(bottom, text='停止', command=self.stop_scan).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text='导出', command=self.export_results).pack(side=tk.LEFT)

        self.init_example_targets()

    def init_example_targets(self):
        example = ['example.com', '192.168.1.1']
        for t in example:
            self.targets_text.insert(tk.END, t + '\n')

    def paste_from_clipboard(self):
        try:
            text = self.root.clipboard_get()
        except Exception:
            messagebox.showwarning('剪贴板', '读取剪贴板失败或为空')
            return
        existing = self.targets_text.get('1.0', tk.END).strip()
        new = (existing + '\n' + text) if existing else text
        self.targets_text.delete('1.0', tk.END)
        self.targets_text.insert('1.0', new)

    def import_targets(self):
        file_path = filedialog.askopenfilename(title='选择目标文件', filetypes=[('文本','*.txt'),('所有','*.*')])
        if not file_path:
            return
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw = f.read()
        except Exception as e:
            messagebox.showerror('导入错误', str(e))
            return
        # 解析并去重目标：优先按行解析 JSON 中的 host 字段，其次提取 host:port，再裸 IP/域名
        seen = set()
        targets = []

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # 尝试解析为 JSON 行，优先使用其中的 host 字段
            parsed_host = None
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    # 支持 nested host key
                    if 'host' in obj and obj['host']:
                        parsed_host = str(obj['host']).strip()
            except Exception:
                parsed_host = None

            if parsed_host:
                h = parsed_host
                if h not in seen:
                    seen.add(h)
                    targets.append(h)
                continue

            # 否则把原始行加入候选（后面再做更多提取）
            if line not in seen:
                seen.add(line)
                targets.append(line)

        # 额外从整个文本中提取 host 字段与 host:port （补充）
        if self.extract_ip_var.get():
            host_fields = re.findall(r'"host"\s*:\s*"([^\"]+)"', raw, flags=re.IGNORECASE)
            for h in host_fields:
                h = h.strip()
                if h and h not in seen:
                    seen.add(h)
                    targets.append(h)

            # 带端口的 IP 或域名
            for hp in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b", raw):
                if hp not in seen:
                    seen.add(hp)
                    targets.append(hp)
            for hp in re.findall(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}:\d{1,5}\b", raw):
                if hp not in seen:
                    seen.add(hp)
                    targets.append(hp)

            # 裸 IPv4
            for ip in re.findall(r"\b(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}\b", raw):
                if ip not in seen:
                    seen.add(ip)
                    targets.append(ip)

            # 裸域名（排除看起来像 IP 的）
            for d in re.findall(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,63})+)\b", raw):
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
                    continue
                if d not in seen:
                    seen.add(d)
                    targets.append(d)

        # 规范化并写回 targets_text
        normalized = []
        for it in targets:
            try:
                normalized.append(self.normalize_target(it))
            except Exception:
                # 如果规范化失败，尝试清理可能的包裹符号
                cleaned = it.strip().strip('"').strip("'")
                try:
                    normalized.append(self.normalize_target(cleaned))
                except Exception:
                    normalized.append(cleaned)

        self.targets_text.delete('1.0', tk.END)
        self.targets_text.insert('1.0', '\n'.join(normalized))
        self.status_var.set(f'已导入 {len(normalized)} 个目标')

    def normalize_target(self, t: str) -> str:
        t = t.strip()
        if not t:
            return t
        parsed = urlparse(t)
        scheme = parsed.scheme
        netloc = parsed.netloc
        path = parsed.path
        if not scheme:
            scheme = self.default_scheme.get() if getattr(self, 'default_scheme', None) else 'http'
        # 如果用户输入像 host:port 或 ip ，urlparse 会把它当做path
        if not netloc:
            candidate = t
            if candidate.startswith('//'):
                candidate = candidate[2:]
            if '://' in candidate:
                parsed = urlparse(candidate)
                netloc = parsed.netloc
                path = parsed.path
            else:
                if '/' in candidate:
                    parts = candidate.split('/', 1)
                    netloc = parts[0]
                    path = '/' + parts[1]
                else:
                    netloc = candidate
                    # candidate 没有路径部分，确保 path 不重复包含 netloc
                    path = ''
        # add default port if provided
        default_port = self.default_port_var.get() if getattr(self, 'default_port_var', None) else ''
        if default_port and ':' not in netloc:
            netloc = f"{netloc}:{default_port}"
        # ensure path
        default_suffix = self.default_suffix_var.get() if getattr(self, 'default_suffix_var', None) else '/'
        if not path or path == '':
            path = default_suffix
        rebuilt = urlunparse((scheme, netloc, path, '', '', ''))
        return rebuilt

    def get_targets(self):
        text = self.targets_text.get('1.0', tk.END).strip()
        if not text:
            return []
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        out = []
        for l in lines:
            try:
                out.append(self.normalize_target(l))
            except Exception:
                out.append(l)
        return out

    def get_request_config(self):
        try:
            timeout = float(self.timeout_var.get())
            threads = int(self.threads_var.get())

            # 解析原始请求模板（若存在）
            raw_tpl = self.raw_request_text.get('1.0', tk.END).strip()
            if raw_tpl:
                parsed = self.parse_raw_request_template(raw_tpl)
            else:
                parsed = None

            return {
                'method': self.method_var.get(),
                'headers': {},
                'body': '',
                'timeout': timeout,
                'threads': threads,
                'template': parsed
            }
        except ValueError:
            messagebox.showerror('配置错误', '超时和线程必须为数字')
            return None

    def parse_raw_request_template(self, raw: str):
        """解析原始HTTP请求模板为 method, path/url, headers, body。"""
        # 统一换行
        lines = raw.replace('\r\n', '\n').split('\n')
        if not lines:
            return None
        first = lines[0].strip()
        parts = first.split()
        if len(parts) >= 2:
            method = parts[0].upper()
            path = parts[1]
        else:
            method = self.method_var.get()
            path = '/'

        headers = {}
        body_lines = []
        i = 1
        # parse headers until empty line
        while i < len(lines):
            line = lines[i]
            i += 1
            if line == '':
                break
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()

        # remaining lines are body
        if i < len(lines):
            body_lines = lines[i:]
        body = '\n'.join(body_lines)
        return {
            'method': method,
            'path': path,
            'headers': headers,
            'body': body
        }

    def start_scan(self):
        if self.scanning:
            messagebox.showwarning('警告', '扫描正在进行')
            return
        targets = self.get_targets()
        if not targets:
            messagebox.showwarning('警告', '请先输入目标')
            return
        config = self.get_request_config()
        if not config:
            return

        # 清空
        for it in self.results_tree.get_children():
            self.results_tree.delete(it)
        self.results = []

        # enqueue
        for t in targets:
            self.requests_queue.put(t)

        self.scanning = True
        self.status_var.set(f'正在扫描 {len(targets)} 个目标...')

        # start workers
        self.threads = []
        for i in range(min(config['threads'], len(targets))):
            th = threading.Thread(target=self.worker_thread, args=(config,), daemon=True)
            th.start()
            self.threads.append(th)

        # updater thread
        updater = threading.Thread(target=self.update_results_thread, daemon=True)
        updater.start()

    def worker_thread(self, config):
        while self.scanning and not self.requests_queue.empty():
            try:
                target = self.requests_queue.get(timeout=1)
            except queue.Empty:
                break
            try:
                res = self.send_request(target, config)
                self.results.append(res)
                self.requests_queue.task_done()
            except Exception as e:
                self.results.append({
                    'target': target,
                    'status': '错误',
                    'title': '请求异常',
                    'banner': str(e),
                    'content_length': 0,
                    'time': 0,
                    'error': True
                })
                try:
                    self.requests_queue.task_done()
                except Exception:
                    pass

    def send_request(self, target, config):
        start = datetime.now()
        try:
            tpl = config.get('template')
            if tpl:
                # 使用模板构建每个目标的 URL、头和 body（替换 Host）
                parsed_target = urlparse(target)
                # path in tpl may be full URL or path
                path = tpl.get('path', '/')
                if path.startswith('http://') or path.startswith('https://'):
                    url = path
                else:
                    url = urlunparse((parsed_target.scheme, parsed_target.netloc, path, '', '', ''))

                headers = tpl.get('headers', {}).copy()
                # 覆盖或设置 Host
                headers['Host'] = parsed_target.netloc

                body_str = tpl.get('body', '')
                # 保持原始字节（尽量保留 multipart 边界等）
                try:
                    body_bytes = body_str.encode('latin-1')
                except Exception:
                    body_bytes = body_str.encode('utf-8', errors='replace')

                resp = requests.request(method=tpl.get('method', config.get('method')), url=url, headers=headers, data=body_bytes, timeout=config.get('timeout', 10), verify=False)
            else:
                kwargs = {
                    'headers': config.get('headers', {}),
                    'timeout': config.get('timeout', 10),
                    'verify': False
                }
                if config['method'] in ['POST','PUT'] and config.get('body'):
                    kwargs['data'] = config['body']
                resp = requests.request(method=config['method'], url=target, **kwargs)
            end = datetime.now()
            ms = int((end - start).total_seconds() * 1000)
            title = '未获取到title'
            ctype = resp.headers.get('Content-Type','')
            if 'text/html' in ctype.lower():
                m = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE|re.DOTALL)
                if m:
                    title = m.group(1).strip()[:120]
            banner = resp.headers.get('Server','未知')
            cl = resp.headers.get('Content-Length', len(resp.content))
            return {
                'target': target,
                'status': resp.status_code,
                'title': title,
                'banner': banner,
                'content_length': cl,
                'time': f'{ms}ms',
                'response': resp,
                'error': False
            }
        except requests.exceptions.Timeout:
            ms = int((datetime.now() - start).total_seconds() * 1000)
            return {
                'target': target,
                'status': '超时',
                'title': '请求超时',
                'banner': f'超过 {config.get("timeout")} 秒',
                'content_length': 0,
                'time': f'{ms}ms',
                'error': True
            }
        except Exception as e:
            ms = int((datetime.now() - start).total_seconds() * 1000)
            return {
                'target': target,
                'status': '错误',
                'title': '请求异常',
                'banner': str(e)[:120],
                'content_length': 0,
                'time': f'{ms}ms',
                'error': True
            }

    def update_results_thread(self):
        processed = 0
        while self.scanning or processed < len(self.results):
            if processed < len(self.results):
                for i in range(processed, len(self.results)):
                    r = self.results[i]
                    self.root.after(0, self.add_result_to_table, r)
                    processed += 1
                    self.status_var.set(f'已扫描 {processed} 个目标...')
            threading.Event().wait(0.12)
        self.root.after(0, self.scan_completed)

    def add_result_to_table(self, result):
        tags = ()
        if result.get('error'):
            tags = ('error',)
        elif isinstance(result.get('status'), int):
            s = result['status']
            if 200 <= s < 300:
                tags = ('success',)
            elif 300 <= s < 400:
                tags = ('redirect',)
            elif 400 <= s < 500:
                tags = ('client_error',)
            elif 500 <= s < 600:
                tags = ('server_error',)
        self.results_tree.insert('', tk.END, values=(result['target'], result['status'], result['title'], result['banner'], result['content_length'], result['time']), tags=tags)

    def on_result_select(self, event):
        sel = self.results_tree.selection()
        if not sel:
            return
        item = sel[0]
        vals = self.results_tree.item(item, 'values')
        target = vals[0]
        result = None
        for r in self.results:
            if r.get('target') == target:
                result = r
                break
        if not result:
            return
        preview = f"目标: {result.get('target')}\n状态: {result.get('status')}\n标题: {result.get('title')}\n服务器: {result.get('banner')}\n响应时间: {result.get('time')}\n\n"
        if 'response' in result and not result.get('error'):
            resp = result['response']
            preview += f"Content-Type: {resp.headers.get('Content-Type','')}\n\n"
            try:
                body = resp.text
            except Exception:
                body = resp.content.decode(errors='replace')
            preview += body[:8000]
            if len(body) > 8000:
                preview += '\n... (已截断)'
        else:
            preview += f"错误信息: {result.get('banner')}"
        self.preview_text.configure(state='normal')
        self.preview_text.delete('1.0', tk.END)
        self.preview_text.insert('1.0', preview)
        self.preview_text.configure(state='disabled')

    def show_result_details(self, event):
        sel = self.results_tree.selection()
        if not sel:
            return
        item = sel[0]
        vals = self.results_tree.item(item, 'values')
        target = vals[0]
        result = None
        for r in self.results:
            if r.get('target') == target:
                result = r
                break
        if not result:
            return
        # 详情窗口
        detail = tk.Toplevel(self.root)
        detail.title('请求详情')
        detail.geometry('900x700')

        top = ttk.Frame(detail)
        top.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(top, text=f"目标: {result.get('target')}", font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W)
        ttk.Label(top, text=f"状态: {result.get('status')}    标题: {result.get('title')}    服务器: {result.get('banner')}").pack(anchor=tk.W, pady=(4,0))

        nb = ttk.Notebook(detail)
        nb.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # headers
        hframe = ttk.Frame(nb)
        htxt = scrolledtext.ScrolledText(hframe, wrap=tk.NONE, font=('Consolas', 10))
        htxt.pack(fill=tk.BOTH, expand=True)
        if 'response' in result and not result.get('error'):
            for k, v in result['response'].headers.items():
                htxt.insert(tk.END, f"{k}: {v}\n")
        htxt.configure(state='disabled')
        nb.add(hframe, text='响应头')

        # body
        bframe = ttk.Frame(nb)
        btxt = scrolledtext.ScrolledText(bframe, wrap=tk.WORD, font=('Consolas', 10))
        btxt.pack(fill=tk.BOTH, expand=True)
        if 'response' in result and not result.get('error'):
            try:
                ctype = result['response'].headers.get('Content-Type','')
                if 'application/json' in ctype:
                    parsed = json.loads(result['response'].text)
                    btxt.insert(tk.END, json.dumps(parsed, indent=2, ensure_ascii=False))
                else:
                    btxt.insert(tk.END, result['response'].text)
            except Exception:
                try:
                    btxt.insert(tk.END, result['response'].content.decode(errors='replace'))
                except Exception:
                    btxt.insert(tk.END, str(result.get('response')))
        else:
            btxt.insert(tk.END, f"错误: {result.get('banner')}")
        btxt.configure(state='disabled')
        nb.add(bframe, text='响应体')

        # raw
        rframe = ttk.Frame(nb)
        rtxt = scrolledtext.ScrolledText(rframe, wrap=tk.NONE, font=('Consolas', 10))
        rtxt.pack(fill=tk.BOTH, expand=True)
        if 'response' in result and not result.get('error'):
            try:
                raw = result['response'].content
                if isinstance(raw, bytes):
                    raw = raw.decode(errors='replace')
                rtxt.insert(tk.END, raw)
            except Exception:
                rtxt.insert(tk.END, str(result.get('response')))
        rtxt.configure(state='disabled')
        nb.add(rframe, text='Raw')

        # 保存按钮
        fbtn = ttk.Frame(detail)
        fbtn.pack(fill=tk.X, padx=8, pady=6)
        def save_body():
            if 'response' not in result:
                messagebox.showinfo('提示', '无响应可保存')
                return
            sp = filedialog.asksaveasfilename(title='保存响应体', defaultextension='.txt', filetypes=[('文本','*.txt'),('所有','*.*')])
            if not sp:
                return
            try:
                with open(sp, 'w', encoding='utf-8') as f:
                    f.write(result['response'].text)
                messagebox.showinfo('保存完成', f'已保存到 {sp}')
            except Exception as e:
                messagebox.showerror('保存错误', str(e))
        ttk.Button(fbtn, text='保存响应体', command=save_body).pack(side=tk.RIGHT)
        ttk.Button(fbtn, text='关闭', command=detail.destroy).pack(side=tk.RIGHT, padx=6)

    def stop_scan(self):
        if not self.scanning:
            return
        self.scanning = False
        self.status_var.set('正在停止扫描...')
        while not self.requests_queue.empty():
            try:
                self.requests_queue.get_nowait()
                self.requests_queue.task_done()
            except Exception:
                break
        for th in self.threads:
            th.join(timeout=1)
        self.threads = []
        self.status_var.set('扫描已停止')

    def scan_completed(self):
        self.scanning = False
        self.status_var.set(f'扫描完成，共处理 {len(self.results)} 个目标')
        for th in self.threads:
            try:
                th.join(timeout=0.5)
            except Exception:
                pass
        self.threads = []

    def export_results(self):
        if not self.results:
            messagebox.showwarning('警告', '没有结果可导出')
            return
        fp = filedialog.asksaveasfilename(title='保存结果', defaultextension='.json', filetypes=[('JSON','*.json'),('CSV','*.csv'),('文本','*.txt')])
        if not fp:
            return
        try:
            if fp.endswith('.json'):
                data = []
                for r in self.results:
                    rc = r.copy()
                    rc.pop('response', None)
                    data.append(rc)
                with open(fp, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            elif fp.endswith('.csv'):
                import csv
                with open(fp, 'w', newline='', encoding='utf-8-sig') as f:
                    w = csv.writer(f)
                    w.writerow(['目标','状态','标题','服务器','内容长度','响应时间'])
                    for r in self.results:
                        w.writerow([r.get('target'), r.get('status'), r.get('title'), r.get('banner'), r.get('content_length'), r.get('time')])
            else:
                with open(fp, 'w', encoding='utf-8') as f:
                    for r in self.results:
                        f.write(str({k: v for k, v in r.items() if k != 'response'}) + '\n')
            messagebox.showinfo('导出完成', f'保存到 {fp}')
        except Exception as e:
            messagebox.showerror('导出错误', str(e))

    def clear_targets(self):
        self.targets_text.delete('1.0', tk.END)


def main():
    try:
        import requests  # ensure installed
    except Exception:
        print('请先安装 requests: pip install requests')
        return
    root = tk.Tk()
    app = BatchHttpScanner(root)
    root.mainloop()


if __name__ == '__main__':
    main()
    def worker_thread(self, config):
        """工作线程函数，处理HTTP请求"""
        while self.scanning and not self.requests_queue.empty():
            try:
                target = self.requests_queue.get(timeout=1)
                
                # 发送HTTP请求
                result = self.send_request(target, config)
                
                # 将结果添加到列表
                self.results.append(result)
                
                self.requests_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                error_result = {
                    "target": target,
                    "status": "错误",
                    "title": "请求失败",
                    "banner": str(e),
                    "content_length": 0,
                    "time": 0,
                    "error": True
                }
                self.results.append(error_result)
                self.requests_queue.task_done()
    
    def send_request(self, target, config):
        """发送HTTP请求并获取响应信息"""
        start_time = datetime.now()
        
        try:
            # 准备请求参数
            kwargs = {
                "headers": config["headers"],
                "timeout": config["timeout"],
                "verify": False  # 忽略SSL证书验证
            }
            
            # 添加请求体（如果是POST/PUT等方法）
            if config["method"] in ["POST", "PUT"] and config["body"]:
                kwargs["data"] = config["body"]
            
            # 发送请求
            response = requests.request(
                method=config["method"],
                url=target,
                **kwargs
            )
            
            # 计算响应时间
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds() * 1000  # 毫秒
            
            # 提取标题
            title = "未获取到title"
            if 'text/html' in response.headers.get('Content-Type', '').lower():
                # 尝试从HTML中提取标题
                title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip()[:50]  # 限制长度
            
            # 获取服务器信息
            banner = response.headers.get('Server', '未知')
            
            # 获取内容长度
            content_length = response.headers.get('Content-Length', len(response.content))
            
            return {
                "target": target,
                "status": response.status_code,
                "title": title,
                "banner": banner,
                "content_length": content_length,
                "time": f"{response_time:.0f}ms",
                "response": response,
                "error": False
            }
            
        except requests.exceptions.Timeout:
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            return {
                "target": target,
                "status": "超时",
                "title": "请求超时",
                "banner": f"超过 {config['timeout']} 秒",
                "content_length": 0,
                "time": f"{response_time:.0f}ms",
                "error": True
            }
            
        except Exception as e:
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds() * 1000
            
            return {
                "target": target,
                "status": "错误",
                "title": "请求异常",
                "banner": str(e)[:50],  # 限制长度
                "content_length": 0,
                "time": f"{response_time:.0f}ms",
                "error": True
            }
    
    def update_results_thread(self):
        """更新结果表格的线程"""
        processed_results = 0
        
        while self.scanning or processed_results < len(self.results):
            if processed_results < len(self.results):
                # 获取新结果
                for i in range(processed_results, len(self.results)):
                    result = self.results[i]
                    
                    # 在UI线程中更新表格
                    self.root.after(0, self.add_result_to_table, result)
                    
                    # 更新状态
                    processed_results += 1
                    self.status_var.set(f"已扫描 {processed_results} 个目标...")
            
            # 短暂休眠
            threading.Event().wait(0.1)
        
        # 扫描完成
        self.root.after(0, self.scan_completed)
    
    def add_result_to_table(self, result):
        """将结果添加到表格"""
        # 根据状态码设置行颜色
        tags = ()
        if result.get("error"):
            tags = ("error",)
        elif isinstance(result.get("status"), int):
            if 200 <= result["status"] < 300:
                tags = ("success",)
            elif 300 <= result["status"] < 400:
                tags = ("redirect",)
            elif 400 <= result["status"] < 500:
                tags = ("client_error",)
            elif 500 <= result["status"] < 600:
                tags = ("server_error",)
        
        # 插入行
        self.results_tree.insert("", tk.END, values=(
            result["target"],
            result["status"],
            result["title"],
            result["banner"],
            result["content_length"],
            result["time"]
        ), tags=tags)
        
        # 标签样式已在表格创建时配置
    
    def scan_completed(self):
        """扫描完成后的处理"""
        self.scanning = False
        self.status_var.set(f"扫描完成，共处理 {len(self.results)} 个目标")
        
        # 等待所有线程完成
        for thread in self.threads:
            thread.join(timeout=1)
        
        self.threads = []
    
    def stop_scan(self):
        """停止扫描"""
        if not self.scanning:
            return
        
        self.scanning = False
        self.status_var.set("正在停止扫描...")
        
        # 清空队列
        while not self.requests_queue.empty():
            try:
                self.requests_queue.get_nowait()
                self.requests_queue.task_done()
            except queue.Empty:
                break
        
        # 等待线程结束
        for thread in self.threads:
            thread.join(timeout=2)
        
        self.threads = []
        self.status_var.set("扫描已停止")
    
    def show_result_details(self, event):
        """显示结果详细信息"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        # 获取选中的行
        item = selection[0]
        values = self.results_tree.item(item, "values")
        
        # 查找对应的完整结果
        target = values[0]
        result = None
        for r in self.results:
            if r["target"] == target:
                result = r
                break
        
        if not result:
            return
        
        # 创建详情窗口
        detail_window = tk.Toplevel(self.root)
        detail_window.title("请求详情")
        detail_window.geometry("900x700")

        # 顶部概览
        overview = ttk.Frame(detail_window)
        overview.pack(fill=tk.X, padx=10, pady=6)

        ttk.Label(overview, text=f"目标URL: {result['target']}", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky=tk.W)
        ttk.Label(overview, text=f"状态: {result['status']}").grid(row=1, column=0, sticky=tk.W, pady=(4,0))
        ttk.Label(overview, text=f"标题: {result['title']}").grid(row=2, column=0, sticky=tk.W, pady=(2,0))
        ttk.Label(overview, text=f"服务器: {result['banner']}").grid(row=3, column=0, sticky=tk.W, pady=(2,0))
        ttk.Label(overview, text=f"内容长度: {result['content_length']}    响应时间: {result['time']}").grid(row=4, column=0, sticky=tk.W, pady=(2,0))

        # 如果没有响应对象，显示错误信息
        if 'response' not in result or result.get('error'):
            err_text = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD, font=('Consolas', 10), height=20)
            err_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)
            err_text.insert('1.0', f"无响应对象或请求发生错误。\n详情: {result.get('banner')}")
            err_text.configure(state='disabled')

            btn_frame = ttk.Frame(detail_window)
            btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
            ttk.Button(btn_frame, text="关闭", command=detail_window.destroy).pack(side=tk.RIGHT)
            return

        response = result['response']

        # 使用Notebook显示多个视图：响应头、响应体（渲染/格式化）、原始数据
        notebook = ttk.Notebook(detail_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        # 响应头标签
        headers_frame = ttk.Frame(notebook)
        headers_text = scrolledtext.ScrolledText(headers_frame, wrap=tk.NONE, font=('Consolas', 10))
        headers_text.pack(fill=tk.BOTH, expand=True)
        headers_out = ''
        for k, v in response.headers.items():
            headers_out += f"{k}: {v}\n"
        headers_text.insert('1.0', headers_out)
        headers_text.configure(state='disabled')
        notebook.add(headers_frame, text='响应头')

        # 响应体标签（渲染/格式化）
        body_frame = ttk.Frame(notebook)
        body_text = scrolledtext.ScrolledText(body_frame, wrap=tk.WORD, font=('Consolas', 10))
        body_text.pack(fill=tk.BOTH, expand=True)

        content_type = response.headers.get('Content-Type', '').lower()
        body_display = ''
        try:
            if 'application/json' in content_type:
                parsed_json = json.loads(response.text)
                body_display = json.dumps(parsed_json, indent=2, ensure_ascii=False)
            else:
                # 对HTML和纯文本直接显示（会进行安全解码）
                body_display = response.text
        except Exception:
            body_display = response.text if isinstance(response.text, str) else response.content.decode(errors='replace')

        body_text.insert('1.0', body_display[:200000])
        if len(body_display) > 200000:
            body_text.insert(tk.END, '\n... (内容已截断)')
        body_text.configure(state='disabled')
        notebook.add(body_frame, text='响应体')

        # 原始数据标签
        raw_frame = ttk.Frame(notebook)
        raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.NONE, font=('Consolas', 10))
        raw_text.pack(fill=tk.BOTH, expand=True)
        try:
            raw = response.content
            if isinstance(raw, bytes):
                raw = raw.decode(errors='replace')
        except Exception:
            raw = str(response)
        raw_text.insert('1.0', raw[:500000])
        if len(raw) > 500000:
            raw_text.insert(tk.END, '\n... (内容已截断)')
        raw_text.configure(state='disabled')
        notebook.add(raw_frame, text='Raw')

        # 底部按钮：保存响应、关闭
        btn_frame = ttk.Frame(detail_window)
        btn_frame.pack(fill=tk.X, padx=10, pady=(6, 10))

        def save_response_body():
            save_path = filedialog.asksaveasfilename(title='保存响应体', defaultextension='.txt', filetypes=[('文本文件','*.txt'),('所有文件','*.*')])
            if not save_path:
                return
            try:
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(body_display)
                messagebox.showinfo('保存成功', f'响应体已保存到:\n{save_path}')
            except Exception as e:
                messagebox.showerror('保存错误', str(e))

        ttk.Button(btn_frame, text='保存响应体', command=save_response_body).pack(side=tk.RIGHT, padx=(0,6))
        ttk.Button(btn_frame, text='关闭', command=detail_window.destroy).pack(side=tk.RIGHT)

    def paste_from_clipboard(self):
        """从系统剪贴板粘贴内容到目标框（按行追加）"""
        try:
            clip = self.root.clipboard_get()
        except Exception:
            messagebox.showwarning('剪贴板为空', '无法读取剪贴板或剪贴板为空')
            return

        existing = self.targets_text.get('1.0', tk.END).strip()
        if existing:
            new_text = existing + '\n' + clip
        else:
            new_text = clip

        self.targets_text.delete('1.0', tk.END)
        self.targets_text.insert('1.0', new_text)

    def on_result_select(self, event):
        """当选择结果时，在右侧预览框显示简要响应内容"""
        sel = self.results_tree.selection()
        if not sel:
            return
        item = sel[0]
        values = self.results_tree.item(item, 'values')
        target = values[0]

        # 查找对应结果
        result = None
        for r in self.results:
            if r.get('target') == target:
                result = r
                break

        if not result:
            return

        # 构建预览文本
        preview = f"目标: {result.get('target')}\n状态: {result.get('status')}\n标题: {result.get('title')}\n服务器: {result.get('banner')}\n响应时间: {result.get('time')}\n\n"
        if 'response' in result and not result.get('error'):
            resp = result['response']
            ct = resp.headers.get('Content-Type','')
            preview += f"Content-Type: {ct}\n\n"
            # 显示适量内容
            try:
                body = resp.text
            except Exception:
                body = resp.content.decode(errors='replace')

            preview += body[:5000]
            if len(body) > 5000:
                preview += '\n... (已截断)'
        else:
            preview += f"错误信息: {result.get('banner')}"

        self.preview_text.configure(state='normal')
        self.preview_text.delete('1.0', tk.END)
        self.preview_text.insert('1.0', preview)
        self.preview_text.configure(state='disabled')
    
    def export_results(self):
        """导出结果到文件"""
        if not self.results:
            messagebox.showwarning("警告", "没有结果可导出")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="保存结果",
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("文本文件", "*.txt"), ("CSV文件", "*.csv")]
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                # 导出为JSON
                with open(file_path, 'w', encoding='utf-8') as f:
                    # 移除响应对象（不可序列化）
                    export_data = []
                    for result in self.results:
                        result_copy = result.copy()
                        result_copy.pop('response', None)
                        export_data.append(result_copy)
                    
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                    
            elif file_path.endswith('.csv'):
                # 导出为CSV
                import csv
                with open(file_path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(["目标", "状态", "标题", "服务器信息", "内容长度", "响应时间"])
                    
                    for result in self.results:
                        writer.writerow([
                            result["target"],
                            result["status"],
                            result["title"],
                            result["banner"],
                            result["content_length"],
                            result["time"]
                        ])
            else:
                # 导出为文本
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("批量HTTP请求扫描结果\n")
                    f.write("=" * 80 + "\n\n")
                    
                    for i, result in enumerate(self.results, 1):
                        f.write(f"目标 {i}: {result['target']}\n")
                        f.write(f"状态: {result['status']}\n")
                        f.write(f"标题: {result['title']}\n")
                        f.write(f"服务器信息: {result['banner']}\n")
                        f.write(f"内容长度: {result['content_length']}\n")
                        f.write(f"响应时间: {result['time']}\n")
                        f.write("-" * 80 + "\n")
            
            self.status_var.set(f"结果已导出到: {file_path}")
            messagebox.showinfo("导出成功", f"结果已成功导出到:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("导出错误", f"导出失败: {str(e)}")

def main():
    """主函数"""
    root = tk.Tk()
    app = BatchHttpScanner(root)
    root.mainloop()

if __name__ == "__main__":
    # 检查依赖
    try:
        import requests
    except ImportError:
        print("请先安装requests库: pip install requests")
        exit(1)
    
    main()