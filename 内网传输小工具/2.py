import os
import time
import socket
import threading
from flask import Flask, request, redirect, url_for, send_from_directory, render_template_string, send_file, Response, stream_with_context, jsonify
import mimetypes
import platform
import json
from datetime import datetime
import functools 
from urllib.parse import quote 
import unicodedata # <-- 关键修复：导入 Unicode 库

# ==============================================================================
# 1. 密码配置 (请修改 ACCESS_PASSWORD 为你自己的密码)
# ==============================================================================
ACCESS_PASSWORD = "88889999" 

# 创建Flask应用
app = Flask(__name__)

# 配置上传文件夹
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 * 10  # 10GB文件大小限制

# 确保上传文件夹存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 聊天消息存储
CHAT_HISTORY_FILE = 'chat_history.json'
chat_history = []

# ==============================================================================
# 密码提示HTML模板 (省略，与之前相同)
# ==============================================================================
PASSWORD_PROMPT_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>访问受限</title>
    <style>
        body { font-family: 'Microsoft YaHei', sans-serif; background-color: #2c3e50; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-container { background-color: #34495e; padding: 40px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.5); text-align: center; }
        h1 { margin-bottom: 20px; color: #ecf0f1; }
        input[type="password"] { padding: 10px; width: 100%; margin-bottom: 15px; border: 1px solid #7f8c8d; border-radius: 5px; box-sizing: border-box; background-color: #2c3e50; color: #ecf0f1; }
        .btn { background-color: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; transition: background-color 0.3s; width: 100%; }
        .btn:hover { background-color: #2980b9; }
        .error { color: #e74c3c; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>访问受限 - 请输入密码</h1>
        <form method="get" action="/">
            <input type="password" name="password" placeholder="请输入访问密码" required>
            <button type="submit" class="btn">进入系统</button>
        </form>
        <p style="margin-top: 20px; font-size: 12px; color: #95a5a6;">访问地址: http://{{ host_ip }}:{{ port }}</p>
    </div>
</body>
</html>
"""

# ==============================================================================
# 密码装饰器函数 (省略，与之前相同)
# ==============================================================================
def password_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        user_password = request.args.get('password')
        
        if request.method == 'POST':
            form_password = request.form.get('access_password')
            json_data = request.get_json(silent=True)
            json_password = json_data.get('access_password') if json_data else None

            if form_password == ACCESS_PASSWORD or json_password == ACCESS_PASSWORD:
                 return f(*args, **kwargs)

        if user_password == ACCESS_PASSWORD:
            return f(*args, **kwargs)
        
        return render_template_string(PASSWORD_PROMPT_TEMPLATE, host_ip=HOST_IP, port=PORT), 401
    return decorated_function

# ==============================================================================
# 文件操作和系统信息函数 (省略部分，与之前相同)
# ==============================================================================

# 加载聊天历史 (省略，与之前相同)
def load_chat_history():
    global chat_history
    try:
        if os.path.exists(CHAT_HISTORY_FILE):
            with open(CHAT_HISTORY_FILE, 'r', encoding='utf-8') as f:
                chat_history = json.load(f)
    except:
        chat_history = []

# 保存聊天历史 (省略，与之前相同)
def save_chat_history():
    try:
        with open(CHAT_HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(chat_history, f, ensure_ascii=False, indent=2)
    except:
        pass

# 初始化聊天历史
load_chat_history()

def get_local_ip():
    # ... (省略，与之前相同)
    """获取本机内网IP地址"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try:
            host_name = socket.gethostname()
            return socket.gethostbyname(host_name)
        except:
            return "127.0.0.1"

def format_size(size):
    # ... (省略，与之前相同)
    """格式化文件大小为易读格式"""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size/1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size/(1024 * 1024):.1f} MB"
    else:
        return f"{size/(1024 * 1024 * 1024):.1f} GB"

def get_disk_usage(path):
    # ... (省略，与之前相同)
    """获取磁盘使用情况"""
    try:
        if platform.system() == 'Windows':
            import ctypes
            free_bytes = ctypes.c_ulonglong(0)
            total_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p(path), None, ctypes.pointer(total_bytes), ctypes.pointer(free_bytes))
            total = total_bytes.value
            free = free_bytes.value
            used = total - free
            return total, used, free
        else:
            stat = os.statvfs(path)
            total = stat.f_frsize * stat.f_blocks
            free = stat.f_frsize * stat.f_bfree
            used = total - free
            return total, used, free
    except:
        return 0, 0, 0

def get_file_type(filename):
    # ... (省略，与之前相同)
    """根据文件扩展名获取文件类型"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    file_types = {
        'txt': '文本文件', 'pdf': 'PDF文档', 'png': 'PNG图片', 'jpg': 'JPG图片', 'jpeg': 'JPEG图片', 'gif': 'GIF图片', 'bmp': 'BMP图片', 'svg': 'SVG矢量图',
        'doc': 'Word文档', 'docx': 'Word文档', 'xls': 'Excel表格', 'xlsx': 'Excel表格', 'ppt': 'PPT演示文稿', 'pptx': 'PPT演示文稿',
        'zip': '压缩文件', 'rar': '压缩文件', '7z': '压缩文件', 'tar': '压缩文件', 'gz': '压缩文件',
        'mp3': '音频文件', 'wav': '音频文件', 'ogg': '音频文件', 'flac': '音频文件',
        'mp4': 'MP4视频', 'mov': 'MOV视频', 'avi': 'AVI视频', 'mkv': 'MKV视频', 'webm': 'WebM视频', 'flv': 'FLV视频', 'wmv': 'WMV视频',
        'csv': 'CSV文件', 'html': 'HTML文件', 'css': 'CSS文件', 'js': 'JavaScript文件', 'json': 'JSON文件', 'xml': 'XML文件',
        'py': 'Python脚本', 'java': 'Java代码', 'c': 'C代码', 'cpp': 'C++代码',
        'sh': 'Shell脚本', 
        'bat': '批处理脚本',
        'md': 'Markdown文档',
        'yml': 'YAML文件', 
        'sql': 'SQL脚本', 
        'php': 'PHP代码'
    }
    return file_types.get(ext, '其他文件')

def is_previewable(filename):
    # ... (省略，与之前相同)
    """检查文件是否支持预览"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    previewable_extensions = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg',
        'mp3', 'wav', 'ogg', 'flac',
        'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 
        'csv', 'html', 'css', 'js', 'json', 'xml', 'py', 'java', 'c', 'cpp',
        'sh', 'bat', 'md', 'yml', 'sql', 'php'
    }
    return ext in previewable_extensions

def get_mime_type(filename):
    # ... (省略，与之前相同)
    """获取文件的MIME类型（改进版本）"""
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type:
        return mime_type
    
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    mime_types = {
        'txt': 'text/plain', 'pdf': 'application/pdf', 
        'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 
        'gif': 'image/gif', 'bmp': 'image/bmp', 'svg': 'image/svg+xml',
        'doc': 'application/msword', 
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel', 
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt': 'application/vnd.ms-powerpoint', 
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'ogg': 'audio/ogg', 'flac': 'audio/flac',
        'mp4': 'video/mp4', 'mov': 'video/quicktime', 'avi': 'video/x-msvideo', 
        'mkv': 'video/x-matroska', 'webm': 'video/webm', 'flv': 'video/x-flv', 'wmv': 'video/x-ms-wmv',
        'csv': 'text/csv', 'html': 'text/html', 'css': 'text/css', 
        'js': 'application/javascript', 'json': 'application/json', 'xml': 'application/xml',
        'py': 'text/x-python', 'java': 'text/x-java', 'c': 'text/x-c', 'cpp': 'text/x-c++',
        'sh': 'text/x-shellscript', 'bat': 'application/x-bat', 'md': 'text/markdown', 
        'yml': 'text/yaml', 'sql': 'text/x-sql', 'php': 'text/x-php'
    }
    return mime_types.get(ext, 'application/octet-stream')

# ------------------------------------------------------------------------------
# **新增关键函数: 解决跨平台文件名查找问题**
# ------------------------------------------------------------------------------
def resolve_filename(requested_filename):
    """
    尝试在上传目录中找到匹配 requested_filename 的实际文件名。
    处理 URL 解码后的字符串与磁盘上的文件名因 Unicode 规范化不一致而导致的不匹配问题。
    返回磁盘上的实际文件名（string）如果找到，否则返回 None。
    """
    upload_path = app.config['UPLOAD_FOLDER']
    
    # 1. 检查直接路径（最常见的情况）
    if os.path.exists(os.path.join(upload_path, requested_filename)):
        return requested_filename
        
    # 2. 尝试使用 Unicode 规范化形式 (NFC 和 NFD) 进行匹配
    # 请求名转换为 NFC 和 NFD 形式
    requested_nfc = unicodedata.normalize('NFC', requested_filename)
    requested_nfd = unicodedata.normalize('NFD', requested_filename)

    # 遍历磁盘上的所有文件
    for actual_filename in os.listdir(upload_path):
        
        # 磁盘文件名与请求名（NFC/NFD）匹配
        if actual_filename == requested_nfc or actual_filename == requested_nfd:
            return actual_filename
            
        # 磁盘文件名（NFC/NFD）与请求名匹配
        # 这处理了请求名已经是某种形式，但磁盘名是另一种形式的情况
        actual_nfc = unicodedata.normalize('NFC', actual_filename)
        actual_nfd = unicodedata.normalize('NFD', actual_filename)
        
        if actual_nfc == requested_filename or actual_nfd == requested_filename:
             return actual_filename
             
    return None

# ==============================================================================
# 改进的流媒体处理函数 (省略，与之前相同)
# ==============================================================================
def stream_file(path, start, length):
    """文件流式传输生成器"""
    with open(path, 'rb') as f:
        f.seek(start)
        remaining = length
        while remaining > 0:
            chunk_size = min(8192, remaining)
            data = f.read(chunk_size)
            if not data:
                break
            remaining -= len(data)
            yield data

def send_file_partial(path):
    """处理 HTTP Range 请求，实现视频/音频文件的分块传输"""
    range_header = request.headers.get('Range', None)
    
    if not range_header:
        # 如果没有Range头，直接发送完整文件 (用于图片/PDF/正常预览)
        return send_file(path, as_attachment=False, mimetype=get_mime_type(os.path.basename(path)))

    try:
        size = os.path.getsize(path)
        byte_range = range_header.replace('bytes=', '').split('-')
        start = int(byte_range[0]) if byte_range[0] else 0
        end = int(byte_range[1]) if byte_range[1] else size - 1
        
        if start >= size:
            return Response("Range Not Satisfiable", status=416)
        
        end = min(end, size - 1)
        length = end - start + 1
        
        resp = Response(
            stream_with_context(stream_file(path, start, length)),
            status=206,
            mimetype=get_mime_type(os.path.basename(path))
        )
        
        resp.headers.add('Content-Range', f'bytes {start}-{end}/{size}')
        resp.headers.add('Accept-Ranges', 'bytes')
        resp.headers.add('Content-Length', str(length))
        resp.headers.add('Cache-Control', 'no-cache')
        return resp
        
    except Exception as e:
        print(f"Range请求处理错误: {e}")
        return send_file(path, as_attachment=False, mimetype=get_mime_type(os.path.basename(path)))

# ==============================================================================
# HTML 模板 (省略，与之前相同)
# ==============================================================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>内网文件共享与聊天 (深色模式)</title>
    <style>
        /* 深色模式全局样式 */
        body { font-family: 'Microsoft YaHei', sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #1e272e; color: #ecf0f1; }
        .container { background-color: #2c3e50; padding: 25px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.5); }
        h1 { color: #3498db; text-align: center; margin-bottom: 30px; }
        h2 { color: #ecf0f1; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; padding: 20px; background-color: #34495e; border-radius: 8px; }
        
        /* 按钮样式 */
        .btn { background-color: #3498db; color: white; padding: 12px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; transition: all 0.3s; }
        .btn:hover { background-color: #2980b9; transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
        
        /* 文件列表 */
        .file-list { list-style-type: none; padding: 0; }
        .file-item { background-color: #4a637a; padding: 15px; margin-bottom: 12px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; transition: all 0.3s; border-left: 4px solid #3498db; }
        .file-item:hover { background-color: #5d748c; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .file-name { font-weight: bold; font-size: 17px; color: #ecf0f1; word-break: break-all; }
        .file-meta { display: flex; gap: 15px; margin-top: 8px; font-size: 14px; color: #bdc3c7; }
        .file-actions { display: flex; gap: 12px; flex-shrink: 0; margin-left: 15px; }
        .file-action-btn { padding: 10px 15px; border-radius: 6px; text-decoration: none; display: flex; align-items: center; gap: 8px; font-size: 14px; transition: all 0.2s; }
        .preview-btn { background-color: #3498db; color: white; }
        .preview-btn:hover { background-color: #2980b9; }
        .download-btn { background-color: #2ecc71; color: white; }
        .download-btn:hover { background-color: #27ae60; }
        .delete-btn { background-color: #e74c3c; color: white; }
        .delete-btn:hover { background-color: #c0392b; }

        /* 消息和提示 */
        .message { padding: 15px; margin-bottom: 20px; border-radius: 6px; font-size: 16px; transition: opacity 0.5s ease; }
        .success { background-color: #27ae60; color: white; border-left: 5px solid #2ecc71; }
        .error { background-color: #c0392b; color: white; border-left: 5px solid #e74c3c; }
        .info { background-color: #2980b9; color: white; border-left: 5px solid #3498db; }
        
        /* 其它组件 */
        .usage { background-color: #2c3e50; padding: 15px; border-radius: 8px; margin-bottom: 25px; word-break: break-all; }
        .info-card { background-color: #3c526a; padding: 15px; border-radius: 8px; flex: 1; min-width: 250px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        
        /* 文件上传拖放区域 */
        .upload-section { 
            border: 3px dashed #3498db; 
            border-radius: 10px; 
            padding: 30px; 
            text-align: center;
            background-color: #34495e;
            transition: background-color 0.3s;
        }
        input[type="file"] { 
            display: none; 
        }
        .file-input-label {
            display: block;
            background-color: #4a637a;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 6px;
            cursor: pointer;
            margin-bottom: 15px;
            transition: background-color 0.3s;
        }
        .file-input-label:hover {
            background-color: #5d748c;
        }
        
        /* 聊天界面样式 */
        .chat-container { background-color: #4a637a; border-radius: 8px; padding: 15px; margin-top: 20px; }
        .chat-messages { height: 300px; overflow-y: auto; padding: 10px; background-color: #2c3e50; border-radius: 6px; margin-bottom: 15px; }
        .message-item { margin-bottom: 10px; padding: 10px; border-radius: 6px; background-color: #5d748c; text-align: left; }
        .message-item.self { background-color: #3498db; text-align: right; }
        .message-sender { font-weight: bold; color: #2ecc71; }
        .message-item.self .message-sender { color: #ecf0f1; }
        .message-time { font-size: 0.8em; color: #bdc3c7; }
        .chat-input { flex-grow: 1; padding: 10px; border: 1px solid #7f8c8d; border-radius: 6px; background-color: #34495e; color: white; }
        
        /* 进度条样式 */
        #progress-container {
            margin-top: 20px; 
            background-color: #3c526a; 
            padding: 15px; 
            border-radius: 8px;
        }
        #progress-bar {
            height: 100%; 
            width: 0%; 
            background-color: #2ecc71; 
            border-radius: 5px;
            transition: width 0.3s;
        }
        
    </style>
    <script>
        // JS 部分 (省略，与之前相同)
        let ACCESS_PASSWORD = "{{ request.args.get('password', '') }}";
        
        function updateTime() {
            const now = new Date();
            const timeString = now.getFullYear() + '-' + 
                              String(now.getMonth() + 1).padStart(2, '0') + '-' + 
                              String(now.getDate()).padStart(2, '0') + ' ' + 
                              String(now.getHours()).padStart(2, '0') + ':' + 
                              String(now.getMinutes()).padStart(2, '0') + ':' + 
                              String(now.getSeconds()).padStart(2, '0');
            document.getElementById('current-time').textContent = timeString;
            
            setTimeout(updateTime, 1000);
        }
        
        // 文件上传进度条功能
        function handleFileUpload(files) {
            const file = files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append('file', file);
            formData.append('access_password', ACCESS_PASSWORD);
            
            const xhr = new XMLHttpRequest();
            const progressBar = document.getElementById('progress-bar');
            const progressPercent = document.getElementById('progress-percent');
            const progressContainer = document.getElementById('progress-container');
            const uploadStatus = document.getElementById('upload-status');
            const uploadButton = document.getElementById('upload-btn');
            
            uploadButton.disabled = true;
            progressContainer.style.display = 'block';
            progressBar.style.width = '0%';
            progressPercent.textContent = '0%';
            uploadStatus.textContent = `开始上传文件: ${file.name}`;

            xhr.upload.addEventListener('progress', function(e) {
                if (e.lengthComputable) {
                    const percentComplete = Math.round((e.loaded * 100) / e.total);
                    progressBar.style.width = percentComplete + '%';
                    progressPercent.textContent = percentComplete + '%';
                    uploadStatus.textContent = `上传中: ${percentComplete}% (${(e.loaded / 1024 / 1024).toFixed(1)}MB / ${(e.total / 1024 / 1024).toFixed(1)}MB)`;
                }
            }, false);

            xhr.onreadystatechange = function() {
                if (xhr.readyState === 4) {
                    uploadButton.disabled = false; 
                    progressContainer.style.display = 'none'; 

                    if (xhr.status === 200) {
                        const success_msg = encodeURIComponent(JSON.stringify({content: '文件 ' + file.name + ' 上传成功', category: 'success'}));
                        window.location.href = '/?password=' + ACCESS_PASSWORD + '&message=' + success_msg;
                    } else if (xhr.status === 401) {
                         alert('上传失败：密码错误或未授权。');
                         window.location.reload();
                    } else {
                        let error_text = `文件上传失败，状态码: ${xhr.status}`;
                        try {
                            const response = JSON.parse(xhr.responseText);
                            if (response.message) {
                                error_text = response.message;
                            }
                        } catch(e) {
                            // 保持默认错误
                        }
                        const error_msg = encodeURIComponent(JSON.stringify({content: error_text, category: 'error'}));
                        window.location.href = '/?password=' + ACCESS_PASSWORD + '&message=' + error_msg;
                    }
                }
            };
            
            xhr.open('POST', '/upload', true);
            xhr.send(formData);
        }
        
        // 聊天功能
        let username = "用户" + Math.floor(Math.random() * 1000);
        let lastMessageId = 0;
        
        function initChat() {
            const storedUsername = localStorage.getItem('chat_username');
            if (storedUsername) {
                username = storedUsername;
            } else {
                localStorage.setItem('chat_username', username);
            }
            document.getElementById('username').value = username;
            
            loadChatHistory();
            setInterval(loadNewMessages, 2000);
        }
        
        function loadChatHistory() {
            fetch('/chat_history?password=' + ACCESS_PASSWORD)
                .then(response => response.json())
                .then(data => {
                    displayMessages(data, true);
                    lastMessageId = data.length > 0 ? data[data.length - 1].id : 0;
                });
        }
        
        function loadNewMessages() {
            fetch(`/new_messages?last_id=${lastMessageId}&password=${ACCESS_PASSWORD}`)
                .then(response => response.json())
                .then(data => {
                    if (data.length > 0) {
                        displayMessages(data, false);
                        lastMessageId = data[data.length - 1].id;
                        const chatMessages = document.getElementById('chat-messages');
                        chatMessages.scrollTop = chatMessages.scrollHeight;
                    }
                });
        }
        
        function displayMessages(messages, isHistory) {
            const chatMessages = document.getElementById('chat-messages');
            
            if (isHistory) {
                chatMessages.innerHTML = '';
            }

            messages.forEach(msg => {
                const isSelf = msg.sender === username;
                const messageElement = document.createElement('div');
                messageElement.className = `message-item ${isSelf ? 'self' : ''}`;
                
                messageElement.innerHTML = `
                    <div class="message-sender">${msg.sender}</div>
                    <div class="message-content">${msg.message}</div>
                    <div class="message-time">${msg.time}</div>
                `;
                
                chatMessages.appendChild(messageElement);
            });
            
            if (isHistory) {
                chatMessages.scrollTop = chatMessages.scrollHeight;
            }
        }
        
        function sendMessage() {
            const messageInput = document.getElementById('message-input');
            const message = messageInput.value.trim();
            
            if (message) {
                fetch('/send_message', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        sender: username,
                        message: message,
                        access_password: ACCESS_PASSWORD 
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        messageInput.value = '';
                        loadNewMessages();
                    } else if (data.status === 'error') {
                        alert('发送消息失败: 密码错误或无效数据');
                    }
                });
            }
        }
        
        function updateUsername() {
            const newUsername = document.getElementById('username').value.trim();
            if (newUsername) {
                username = newUsername;
                localStorage.setItem('chat_username', username);
                alert('用户名已更新为: ' + username);
            }
        }

        // 页面加载完成后
        document.addEventListener('DOMContentLoaded', function() {
            updateTime();
            initChat();

            // 文件拖放和选择逻辑
            const dropArea = document.querySelector('.upload-section');
            const fileInput = document.querySelector('input[type="file"]');
            const uploadForm = document.querySelector('form[action="/upload"]');
            const fileInputLabel = document.getElementById('file-input-label');

            fileInput.addEventListener('change', function() {
                if (this.files.length) {
                    fileInputLabel.textContent = '已选择文件: ' + this.files[0].name;
                } else {
                    fileInputLabel.textContent = '点击选择文件或拖放到此处';
                }
            });

            dropArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropArea.style.backgroundColor = '#4a637a';
            });
            
            dropArea.addEventListener('dragleave', () => {
                dropArea.style.backgroundColor = '#34495e';
            });
            
            dropArea.addEventListener('drop', (e) => {
                e.preventDefault();
                dropArea.style.backgroundColor = '#34495e';
                
                if (e.dataTransfer.files.length) {
                    fileInput.files = e.dataTransfer.files;
                    fileInputLabel.textContent = '已选择文件: ' + fileInput.files[0].name;
                }
            });
            
            uploadForm.addEventListener('submit', function(e) {
                e.preventDefault();
                if (fileInput.files.length > 0) {
                    handleFileUpload(fileInput.files);
                } else {
                    alert('请先选择文件！');
                }
            });
            
            document.getElementById('message-input').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    sendMessage();
                }
            });
            
            // 自动隐藏消息
            const flashMessage = document.getElementById('flash-message');
            if (flashMessage) {
                setTimeout(() => {
                    flashMessage.style.opacity = '0';
                    setTimeout(() => flashMessage.style.display = 'none', 500);
                }, 5000);
            }
        });
    </script>
</head>
<body>
    <div class="container">
        <h1>内网文件共享与聊天系统</h1>
        
        <div class="time-display" id="current-time">{{ current_time }}</div>
        
        <div class="usage">
            <h3>使用说明：</h3>
            <p>1. 在同一局域网内的设备上，在浏览器中输入以下地址访问：</p>
            <p><strong>http://{{ host_ip }}:{{ port }}</strong></p>
        </div>
        
        <div class="section upload-section">
            <div class="section-title">
                <h2>文件上传</h2>
            </div>
            <form method="post" action="/upload" enctype="multipart/form-data" onsubmit="return false;">
                <div class="form-group">
                    <input type="file" name="file" id="file-input" required>
                    <label for="file-input" class="file-input-label" id="file-input-label">点击选择文件或拖放到此处</label>
                </div>
                <button type="submit" id="upload-btn" class="btn">开始上传</button>
            </form>
            
            <div id="progress-container" style="display: none;">
                <p style="margin-bottom: 10px;">上传进度: <span id="progress-percent">0%</span></p>
                <div style="background-color: #34495e; border-radius: 5px; overflow: hidden; height: 20px;">
                    <div id="progress-bar" style="height: 100%; width: 0%; background-color: #2ecc71;"></div>
                </div>
                <p id="upload-status" style="margin-top: 10px; color: #f1c40f;"></p>
            </div>
        </div>
        
        {% if message %}
        <div class="message {{ message.category }}" id="flash-message">{{ message.content }}</div>
        {% endif %}
        
        <div class="section">
            <div class="section-title">
                <h2>文件列表 <span class="file-count-badge" style="background-color: #2ecc71; color: white; padding: 5px 10px; border-radius: 4px;">{{ file_count }} 个文件</span></h2>
            </div>
            {% if files %}
            <ul class="file-list">
                {% for file in files %}
                <li class="file-item">
                    <div class="file-info">
                        <div class="file-name">{{ file.name }}</div>
                        <div class="file-meta">
                            <span>{{ file.type }}</span>
                            <span>{{ file.size }}</span>
                            <span>{{ file.date }}</span>
                        </div>
                    </div>
                    <div class="file-actions">
                        {% if file.previewable %}
                        <a href="/preview/{{ file.quoted_name }}?password={{ request.args.get('password') }}" class="file-action-btn preview-btn" title="预览">
                            <span>预览</span>
                        </a>
                        {% endif %}
                        <a href="/download/{{ file.quoted_name }}?password={{ request.args.get('password') }}" class="file-action-btn download-btn" title="下载">
                            <span>下载</span>
                        </a>
                        <a href="/delete/{{ file.quoted_name }}?password={{ request.args.get('password') }}" class="file-action-btn delete-btn" title="删除" onclick="return confirm('确定要删除 {{ file.name }} 吗？')">
                            <span>删除</span>
                        </a>
                    </div>
                </li>
                {% endfor %}
            </ul>
            {% else %}
            <div class="empty-state" style="text-align: center; color: #bdc3c7;">
                <div style="font-size: 50px;"></div>
                <h3>没有文件</h3>
                <p>上传文件后，它们将显示在这里</p>
            </div>
            {% endif %}
        </div>
        
        <div class="section">
            <div class="section-title">
                <h2>实时聊天</h2>
            </div>
            <div class="chat-container">
                <div class="chat-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <div>
                        <label for="username" style="color: #ecf0f1;">用户名:</label>
                        <input type="text" id="username" style="padding: 5px; border: 1px solid #7f8c8d; border-radius: 4px; background-color: #34495e; color: white;">
                        <button onclick="updateUsername()" style="padding: 5px 10px; background-color: #2ecc71; color: white; border: none; border-radius: 4px; cursor: pointer;">更新</button>
                    </div>
                    <div style="color: #bdc3c7;">当前用户: <span id="current-user" style="font-weight: bold;">{{ username }}</span></div>
                </div>
                <div id="chat-messages" class="chat-messages">
                    </div>
                <div class="chat-input-container">
                    <input type="text" id="message-input" class="chat-input" placeholder="输入消息...">
                    <button onclick="sendMessage()" class="chat-send-btn btn">发送</button>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">
                <h2>系统信息</h2>
            </div>
            <div class="system-info" style="display: flex; flex-wrap: wrap; gap: 20px; margin-top: 20px;">
                <div class="info-card">
                    <h3>服务器信息</h3>
                    <p>IP地址: {{ host_ip }}</p>
                    <p>端口: {{ port }}</p>
                    <p>存储路径: {{ upload_folder }}</p>
                </div>
                <div class="info-card">
                    <h3>存储状态</h3>
                    <p>磁盘空间: {{ disk_space }}</p>
                    <p>文件数量: {{ file_count }}</p>
                    <p>总文件大小: {{ total_size }}</p>
                </div>
                <div class="info-card">
                    <h3>服务状态</h3>
                    <p>运行时间: {{ uptime }}</p>
                    <p>系统平台: {{ platform }}</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

# 文件预览HTML模板 (省略，与之前相同)
PREVIEW_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>预览文件 - {{ filename }}</title>
    <style>
        /* 深色模式预览样式 */
        body { font-family: 'Microsoft YaHei', sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #1e272e; color: #ecf0f1; }
        .container { background-color: #2c3e50; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.5); }
        h1 { color: #3498db; text-align: center; margin-bottom: 20px; }
        .file-info { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #4a637a; }
        .file-name { font-size: 24px; font-weight: bold; color: #ecf0f1; word-break: break-all; }
        .file-meta { display: flex; justify-content: center; gap: 20px; margin-top: 10px; color: #bdc3c7; }
        .preview-container { background-color: #34495e; padding: 25px; border-radius: 10px; margin-bottom: 25px; }
        .preview-content { max-height: 70vh; overflow: auto; }
        .text-preview { white-space: pre-wrap; font-family: monospace; background-color: #1c2833; color: #a9cce3; padding: 20px; border-radius: 8px; border: 1px solid #3498db; }
        .image-preview { max-width: 100%; max-height: 70vh; display: block; margin: 0 auto; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.3); }
        .video-player { width: 100%; max-height: 70vh; border-radius: 8px; background-color: #000; }
        .audio-player { width: 100%; margin: 20px 0; }
        .action-buttons { display: flex; gap: 15px; justify-content: center; margin-top: 20px; }
        .action-btn { display: inline-block; padding: 12px 25px; text-decoration: none; text-align: center; border-radius: 6px; font-size: 16px; transition: all 0.3s; }
        .back-btn { background-color: #3498db; color: white; }
        .back-btn:hover { background-color: #2980b9; transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
        .download-btn { background-color: #2ecc71; color: white; }
        .download-btn:hover { background-color: #27ae60; }
        .unsupported { text-align: center; padding: 50px; background-color: #34495e; border-radius: 8px; color: #e74c3c; }
        .office-preview { width: 100%; height: 70vh; border: none; border-radius: 8px; }
        .video-info { text-align: center; color: #bdc3c7; margin-top: 10px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>文件预览</h1>
        
        <div class="file-info">
            <div class="file-name">{{ filename }}</div>
            <div class="file-meta">
                <span>类型: {{ file_type }}</span>
                <span>大小: {{ file_size }}</span>
                <span>上传时间: {{ file_date }}</span>
            </div>
        </div>
        
        <div class="preview-container">
            {% if preview_type == 'text' %}
                <div class="preview-content">
                    <pre class="text-preview">{{ file_content }}</pre>
                </div>
            {% elif preview_type == 'image' %}
                <div class="preview-content">
                    <img src="/stream/{{ quoted_filename }}?password={{ request.args.get('password') }}" alt="{{ filename }}" class="image-preview">
                </div>
            {% elif preview_type == 'video' %}
                <div class="preview-content">
                    <video controls class="video-player" preload="metadata">
                        <source src="/stream/{{ quoted_filename }}?password={{ request.args.get('password') }}" type="{{ mime_type }}">
                        您的浏览器不支持视频播放
                    </video>
                    <div class="video-info">支持拖动进度条、音量控制等操作 (提示: .mkv 等格式可能不受浏览器支持)</div>
                </div>
            {% elif preview_type == 'audio' %}
                <div class="preview-content">
                    <audio controls class="audio-player" preload="metadata">
                        <source src="/stream/{{ quoted_filename }}?password={{ request.args.get('password') }}" type="{{ mime_type }}">
                        您的浏览器不支持音频播放
                    </audio>
                </div>
            {% elif preview_type == 'pdf' %}
                <div class="preview-content">
                    <iframe src="/stream/{{ quoted_filename }}?password={{ request.args.get('password') }}" width="100%" height="600px" style="border: none;"></iframe>
                </div>
            {% elif preview_type == 'office' %}
                <div class="unsupported">
                    <h3>Office 文件预览在内网中不可用</h3>
                    <p>此功能需要将文件暴露在公共互联网上，而您的服务器在内网。请下载后查看。</p>
                </div>
            {% else %}
                <div class="unsupported">
                    <h3>不支持在线预览</h3>
                    <p>此文件类型不支持在线预览，请下载后查看</p>
                </div>
            {% endif %}
        </div>
        
        <div class="action-buttons">
            <a href="/?password={{ request.args.get('password') }}" class="action-btn back-btn">返回文件列表</a>
            <a href="/download/{{ quoted_filename }}?password={{ request.args.get('password') }}" class="action-btn download-btn">下载文件</a>
        </div>
    </div>
</body>
</html>
"""

# ==============================================================================
# Flask 路由和视图函数
# ==============================================================================

@app.route('/')
@password_required
def index():
    # ... (省略，与之前相同)
    """显示主页面"""
    files = []
    total_size_bytes = 0
    
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(filepath):
            size = os.path.getsize(filepath)
            total_size_bytes += size
            mtime = os.path.getmtime(filepath)
            date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
            
            # 使用 quote 编码文件名
            quoted_name = quote(filename) 

            files.append({
                'name': filename, 
                'quoted_name': quoted_name, 
                'size': format_size(size),
                'date': date_str,
                'type': get_file_type(filename),
                'previewable': is_previewable(filename)
            })
    
    files.sort(key=lambda x: os.path.getmtime(os.path.join(app.config['UPLOAD_FOLDER'], x['name'])), reverse=True)
    
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    total, used, free = get_disk_usage(app.config['UPLOAD_FOLDER'])
    platform_info = platform.platform()
    
    # 解析消息
    message_json = request.args.get('message')
    try:
        message = json.loads(message_json) if message_json else None
    except:
        message = None
    
    return render_template_string(HTML_TEMPLATE, 
                                 files=files,
                                 file_count=len(files),
                                 host_ip=HOST_IP,
                                 port=PORT,
                                 current_time=current_time,
                                 upload_folder=os.path.abspath(app.config['UPLOAD_FOLDER']),
                                 disk_space=f"已用: {format_size(used)} / 总共: {format_size(total)}",
                                 total_size=format_size(total_size_bytes),
                                 platform=platform_info,
                                 uptime=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                                 message=message,
                                 request=request)

@app.route('/upload', methods=['POST'])
@password_required
def upload_file():
    # ... (省略，与之前相同)
    """处理文件上传 (JSON 响应)"""
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': '没有选择文件'}), 400
    
    file = request.files['file']
    
    try:
        filename = file.filename
        if not filename:
            return jsonify({'status': 'error', 'message': '文件名为空'}), 400

        filename = os.path.basename(filename)
        
        if not filename:
            return jsonify({'status': 'error', 'message': '文件名无效'}), 400
        
        if '..' in filename:
             return jsonify({'status': 'error', 'message': '文件名包含无效字符 (..)'}), 400

        base, ext = os.path.splitext(filename)
        counter = 1
        new_filename = filename
        while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], new_filename)):
            new_filename = f"{base}({counter}){ext}"
            counter += 1
            
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
        return jsonify({'status': 'success', 'filename': new_filename}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'保存文件失败: {str(e)}'}), 500

# ------------------------------------------------------------------------------
# **关键修复应用: 使用 resolve_filename 查找实际文件名**
# ------------------------------------------------------------------------------

@app.route('/download/<path:filename>')
@password_required
def download_file(filename):
    """提供文件下载 (强制下载)"""
    # 查找实际文件名
    actual_filename = resolve_filename(filename)

    if actual_filename is None:
        error_msg = json.dumps({'content': f'文件 {filename} 不存在 (文件名或编码可能不兼容)', 'category': 'error'})
        return redirect(url_for('index', password=request.args.get('password'), message=error_msg))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], actual_filename)

    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'], 
            actual_filename, # <-- 使用实际文件名
            as_attachment=True, 
            mimetype=get_mime_type(actual_filename) # <-- 使用实际文件名
        )
    except Exception as e:
        error_msg = json.dumps({'content': f'下载文件失败: {str(e)}', 'category': 'error'})
        return redirect(url_for('index', password=request.args.get('password'), message=error_msg))

@app.route('/stream/<path:filename>')
@password_required
def stream_video(filename):
    """专用于视频/音频/图片/PDF 的流媒体路由"""
    # 查找实际文件名
    actual_filename = resolve_filename(filename)

    if actual_filename is None:
        return "文件未找到", 404
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], actual_filename)

    try:
        return send_file_partial(filepath)
    except Exception as e:
        print(f"流媒体失败 for {filename}: {e}")
        return "流媒体失败", 500

@app.route('/preview/<path:filename>')
@password_required
def preview_file(filename):
    """预览文件内容"""
    # 查找实际文件名
    actual_filename = resolve_filename(filename)

    if actual_filename is None:
        return redirect(url_for('index', password=request.args.get('password'), 
                              message=json.dumps({'content': f'文件 {filename} 不存在', 'category': 'error'})))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], actual_filename)
    
    size = os.path.getsize(filepath)
    mtime = os.path.getmtime(filepath)
    date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
    file_type = get_file_type(actual_filename)
    mime_type = get_mime_type(actual_filename)
    
    preview_type = 'other'
    file_content = ""
    
    # 使用实际文件名进行编码，用于模板中的 src/href
    quoted_filename = quote(actual_filename) 
    
    ext = actual_filename.split('.')[-1].lower() if '.' in actual_filename else ''
    
    if ext in ['txt', 'csv', 'html', 'css', 'js', 'json', 'xml', 'py', 'java', 'c', 'cpp', 'sh', 'bat', 'md', 'yml', 'sql', 'php']:
        preview_type = 'text'
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                file_content = f.read(1024 * 1024) 
        except UnicodeDecodeError:
            try:
                with open(filepath, 'r', encoding='gbk') as f:
                    file_content = f.read(1024 * 1024)
            except:
                file_content = "文件内容过大或无法解码（已限制预览前1MB）"
        except Exception as e:
            file_content = f"读取文件时出错: {str(e)}"
    
    elif ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg']:
        preview_type = 'image'
    
    elif ext in ['mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv']:
        preview_type = 'video'
    
    elif ext in ['mp3', 'wav', 'ogg', 'flac']:
        preview_type = 'audio'
    
    elif ext == 'pdf':
        preview_type = 'pdf'
    
    elif ext in ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']:
        preview_type = 'office' 
    
    return render_template_string(PREVIEW_TEMPLATE,
                                 filename=actual_filename, # <-- 传入实际文件名给模板显示
                                 file_type=file_type,
                                 file_size=format_size(size),
                                 file_date=date_str,
                                 preview_type=preview_type,
                                 file_content=file_content,
                                 mime_type=mime_type,
                                 quoted_filename=quoted_filename, 
                                 request=request)

@app.route('/delete/<path:filename>')
@password_required
def delete_file(filename):
    """删除文件"""
    # 查找实际文件名
    actual_filename = resolve_filename(filename)

    if actual_filename is None:
        return redirect(url_for('index', password=request.args.get('password'), 
                              message=json.dumps({'content': f'文件 {filename} 不存在', 'category': 'error'})))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], actual_filename)

    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            return redirect(url_for('index', password=request.args.get('password'), 
                                  message=json.dumps({'content': f'文件 {actual_filename} 已删除', 'category': 'success'})))
        except Exception as e:
            return redirect(url_for('index', password=request.args.get('password'), 
                                  message=json.dumps({'content': f'删除文件失败: {str(e)}', 'category': 'error'})))
    else:
        # Should not happen after resolve_filename check, but as a safeguard
        return redirect(url_for('index', password=request.args.get('password'), 
                              message=json.dumps({'content': f'文件 {filename} 不存在', 'category': 'error'})))

# 聊天功能路由 (省略，与之前相同)
@app.route('/chat_history')
@password_required
def get_chat_history():
    return jsonify(chat_history)

@app.route('/new_messages')
@password_required
def get_new_messages():
    last_id = int(request.args.get('last_id', 0))
    new_messages = [msg for msg in chat_history if msg['id'] > last_id]
    return jsonify(new_messages)

@app.route('/send_message', methods=['POST'])
@password_required
def send_message():
    data = request.get_json()
    if data and 'sender' in data and 'message' in data:
        new_message = {
            'id': len(chat_history) + 1,
            'sender': data['sender'],
            'message': data['message'],
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        chat_history.append(new_message)
        save_chat_history()
        return jsonify({'status': 'success', 'message_id': new_message['id']})
    return jsonify({'status': 'error', 'message': 'Invalid data'}), 400

if __name__ == '__main__':
    PORT = 8080
    HOST_IP = get_local_ip()
    
    print(f"=====================================================================")
    print(f"| 内网文件共享服务启动中                                          |")
    print(f"| **请使用以下地址访问 (记得替换 your_secret_password):** |")
    print(f"| **http://{HOST_IP}:{PORT}** |")
    print(f"| 初始密码: {ACCESS_PASSWORD}                                     |")
    print(f"=====================================================================")
    print(f"上传文件夹: {os.path.abspath(UPLOAD_FOLDER)}")
    print("按 Ctrl+C 停止服务")
    
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)