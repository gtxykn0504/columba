import os
import sys
import threading
import time
import smtplib
import json
import ipaddress
import ctypes
import subprocess
import datetime
import logging
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr

import pythoncom
import win32evtlog
import pystray
from PIL import Image

# ========== 常量与目录 ==========
USER_DATA_DIR = os.path.expanduser("~/.columba")
CONFIG_FILE = os.path.join(USER_DATA_DIR, "config.json")
LOG_FILE = os.path.join(USER_DATA_DIR, "login_notifier.log")
FAILURE_JSON_FILE = os.path.join(USER_DATA_DIR, "failure_login.json")
ICON_FILE = "columba.ico"

os.makedirs(USER_DATA_DIR, exist_ok=True)

# ========== 日志配置 ==========
handler = RotatingFileHandler(LOG_FILE, maxBytes=1024*1024, backupCount=0, encoding='utf-8-sig')
handler.setLevel(logging.INFO)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[handler, logging.StreamHandler()]
)
log = logging.info

def show_error(msg):
    ctypes.windll.user32.MessageBoxW(0, msg, "错误", 0x10)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    try:
        script = sys.argv[0] if getattr(sys, 'frozen', False) else sys.executable
        params = f'"{sys.argv[0]}" ' + " ".join(sys.argv[1:]) if not getattr(sys, 'frozen', False) else " ".join(sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", script, params, None, 1)
        if ret > 32:
            log("提权成功，新进程已启动")
        else:
            show_error(f"提权失败 (错误码: {ret})，请手动以管理员身份运行。")
            log(f"提权失败，返回 {ret}")
    except Exception as e:
        log(f"提权异常: {e}")
        show_error(f"提权异常: {e}\n请手动以管理员身份运行。")
    sys.exit(0)

# ========== 配置加载 ==========
def load_config(exit_on_error=True):
    """加载配置文件，exit_on_error=False 时抛出异常而非退出"""
    if not os.path.exists(CONFIG_FILE):
        if exit_on_error:
            show_error(f"配置文件不存在：{CONFIG_FILE}")
            sys.exit(1)
        else:
            raise FileNotFoundError(f"配置文件不存在：{CONFIG_FILE}")

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8-sig") as f:
            cfg = json.load(f)
    except Exception as e:
        if exit_on_error:
            show_error(f"配置文件解析失败：{e}\n请检查 JSON 格式。")
            sys.exit(1)
        else:
            raise

    # 验证 SMTP
    smtp = cfg.get("SMTP")
    required_smtp = ("server", "port", "username", "password", "from_addr", "to_addr")
    if not smtp or not all(k in smtp for k in required_smtp):
        if exit_on_error:
            show_error("配置文件缺少 SMTP 必要字段")
            sys.exit(1)
        else:
            raise ValueError("配置文件缺少 SMTP 必要字段")

    # 验证 MESSAGE
    msg = cfg.get("MESSAGE", {})
    if not msg.get("subject_success") or not msg.get("body_success"):
        if exit_on_error:
            show_error("配置文件缺少 MESSAGE.subject_success 或 body_success")
            sys.exit(1)
        else:
            raise ValueError("缺少 MESSAGE.subject_success 或 body_success")

    # 解析允许的登录类型
    types_str = cfg.get("SETTINGS", {}).get("logon_types", "")
    allowed_types = {int(t.strip()) for t in types_str.split(',') if t.strip().isdigit()}
    if not allowed_types:
        if exit_on_error:
            show_error("配置 SETTINGS.logon_types 无效或为空，请填写数字并用逗号分隔")
            sys.exit(1)
        else:
            raise ValueError("SETTINGS.logon_types 无效或为空")

    # 解析封禁频率
    try:
        ban_frequency = int(cfg.get("SETTINGS", {}).get("ban_frequency", 5))
    except (ValueError, TypeError):
        if exit_on_error:
            show_error("配置 SETTINGS.ban_frequency 异常")
            sys.exit(1)
        else:
            raise ValueError("SETTINGS.ban_frequency 异常")

    return smtp, msg, allowed_types, ban_frequency

def get_logon_type_desc(logon_type):
    desc_map = {
        2: "交互式登录 (Interactive)", 3: "网络登录 (Network)", 4: "批处理登录 (Batch)",
        5: "服务登录 (Service)", 7: "解锁登录 (Unlock)", 8: "网络明文登录 (Network Cleartext)",
        9: "新凭证登录 (New Credentials)", 10: "远程交互式登录 (RemoteInteractive)",
        11: "缓存交互式登录 (CachedInteractive)",
    }
    return desc_map.get(logon_type, f"未知类型 ({logon_type})")

# ========== 邮件发送 ==========
def _send_email_raw(smtp_cfg, subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"] = formataddr(("Columba", smtp_cfg["from_addr"]))
        msg["To"] = smtp_cfg["to_addr"]
        msg["Subject"] = Header(subject, "utf-8")
        msg.attach(MIMEText(body, "plain", "utf-8"))

        if smtp_cfg.get("use_tls", True):
            server = smtplib.SMTP(smtp_cfg["server"], int(smtp_cfg["port"]))
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(smtp_cfg["server"], int(smtp_cfg["port"]))

        server.login(smtp_cfg["username"], smtp_cfg["password"])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        log(f"邮件发送失败: {e}")
        return False

def send_mail(smtp_cfg, msg_cfg, event_data=None, test=False):
    if test:
        subject = "测试邮件 - Columba 通知"
        body = "这是一封测试邮件，您的邮件配置正常。"
    else:
        if not event_data:
            return False
        if "logon_type" in event_data:
            event_data["logon_type_desc"] = get_logon_type_desc(int(event_data["logon_type"]))
        subject = msg_cfg["subject_success"]
        try:
            body = msg_cfg["body_success"].format(**event_data)
        except KeyError as e:
            log(f"邮件模板错误，缺少 {e}")
            body = msg_cfg["body_success"]
    return _send_email_raw(smtp_cfg, subject, body)

# ========== 安全日志监听 ==========
class LoginMonitor:
    def __init__(self, success_cb, failure_cb, allowed_types):
        self.success_cb = success_cb
        self.failure_cb = failure_cb
        self.allowed_logon_types = allowed_types   # 可动态修改
        self.running = True
        self.processed = {}

    def _parse_logon_type(self, strings, index):
        if len(strings) > index:
            try:
                return int(strings[index])
            except ValueError:
                for s in strings:
                    if s.isdigit():
                        return int(s)
        return None

    def _parse_event(self, event):
        try:
            strings = event.StringInserts
            if not strings:
                return None
            time_str = event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S")
            time_fmt = time_str + f",{event.TimeGenerated.microsecond // 1000:03d}"
            computer = os.environ.get("COMPUTERNAME", "Unknown")

            if event.EventID == 4624:  # 成功
                logon_type = self._parse_logon_type(strings, 8)
                if logon_type is None or (self.allowed_logon_types and logon_type not in self.allowed_logon_types):
                    return None
                return {
                    "event_type": "success", "logon_type": logon_type,
                    "username": strings[5] if len(strings) > 5 else "?",
                    "domain": strings[6] if len(strings) > 6 else "?",
                    "process_name": strings[17] if len(strings) > 17 else "?",
                    "source_ip": strings[18] if len(strings) > 18 else "?",
                    "time": time_str, "time_formatted": time_fmt, "computer": computer
                }
            elif event.EventID == 4625:  # 失败
                logon_type = self._parse_logon_type(strings, 10)
                if logon_type is None:
                    return None
                status = strings[7] if len(strings) > 7 else "?"
                substatus = strings[9] if len(strings) > 9 else "?"
                return {
                    "event_type": "failure", "logon_type": logon_type,
                    "username": strings[5] if len(strings) > 5 else "?",
                    "domain": strings[6] if len(strings) > 6 else "?",
                    "failure_reason": f"状态码: {status}, 子状态: {substatus}",
                    "source_ip": strings[19] if len(strings) > 19 else "?",
                    "time": time_str, "time_formatted": time_fmt, "computer": computer
                }
        except Exception as e:
            log(f"解析事件失败: {e}")
        return None

    def run(self):
        pythoncom.CoInitialize()
        log("开始监听安全日志（4624/4625）...")
        while self.running:
            hand = None
            try:
                hand = win32evtlog.OpenEventLog(None, "Security")
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                for evt in events:
                    if evt.EventID not in (4624, 4625) or evt.RecordNumber in self.processed:
                        continue
                    self.processed[evt.RecordNumber] = None
                    if len(self.processed) > 1000:
                        self.processed.pop(next(iter(self.processed)))
                    data = self._parse_event(evt)
                    if data:
                        log(f"检测到事件 {evt.EventID}: {data['username']} (类型 {data.get('logon_type')})")
                        if data["event_type"] == "success":
                            self.success_cb(data)
                        else:
                            self.failure_cb(data)
            except Exception as e:
                log(f"监听出错: {e}")
            finally:
                if hand:
                    win32evtlog.CloseEventLog(hand)
                time.sleep(2 if self.running else 0)
        pythoncom.CoUninitialize()

    def stop(self):
        self.running = False

# ========== 失败登录记录与拦截 ==========
class FailureCollector:
    def __init__(self, smtp_cfg, msg_cfg, ban_frequency):
        # 配置以实例变量存储，支持动态更新
        self.smtp_cfg = smtp_cfg
        self.msg_cfg = msg_cfg
        self.ban_frequency = ban_frequency
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self._start_daily_task()

    def _load_json(self):
        if not os.path.exists(FAILURE_JSON_FILE):
            return {"失败的IP地址": {}}
        try:
            with open(FAILURE_JSON_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log(f"[JSON] 加载失败: {e}")
            return {"失败的IP地址": {}}

    def _save_json(self, data):
        try:
            with open(FAILURE_JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log(f"[JSON] 保存失败: {e}")

    @staticmethod
    def _is_public_ip(ip_str):
        try:
            addr = ipaddress.ip_address(ip_str)
            return not addr.is_private and not addr.is_loopback
        except ValueError:
            return False

    def _is_blocked(self, ip_str):
        rule = f"Columba Block {ip_str}"
        cmd = f'netsh advfirewall firewall show rule name="{rule}"'
        si = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=subprocess.SW_HIDE)
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW)
            return "规则名称:" in (res.stdout + res.stderr)
        except:
            return False

    def _block_ip(self, ip_str):
        rule = f"Columba Block {ip_str}"
        cmd = f'netsh advfirewall firewall add rule name="{rule}" dir=in action=block remoteip={ip_str}'
        si = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=subprocess.SW_HIDE)
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, startupinfo=si, creationflags=subprocess.CREATE_NO_WINDOW)
            if res.returncode == 0:
                log(f"[防火墙] 成功封禁 IP: {ip_str}")
                with self.lock:
                    jdata = self._load_json()
                    ip_entry = jdata.get("失败的IP地址", {}).get(ip_str)
                    if ip_entry:
                        ip_entry["是否添加黑名单"] = "True"
                        self._save_json(jdata)
            else:
                log(f"[防火墙] 封禁 IP {ip_str} 失败: {res.stderr.strip()}")
        except Exception as e:
            log(f"[防火墙] 封禁异常 (IP: {ip_str}): {e}")

    def log_failure(self, data):
        ip = data.get("source_ip")
        if not ip or ip == "?":
            return
        with self.lock:
            jdata = self._load_json()
            ip_dict = jdata.setdefault("失败的IP地址", {})
            entry = ip_dict.setdefault(ip, {"失败总次数": "0", "是否添加黑名单": "False", "登陆记录": []})
            cnt = int(entry["失败总次数"]) + 1
            entry["失败总次数"] = str(cnt)
            entry["登陆记录"].append({
                "时间": data["time_formatted"],
                "用户名": data.get("username", "?"),
                "方式": data.get("logon_type_desc", "未知")
            })
            self._save_json(jdata)

            if (self.ban_frequency > 0 and cnt >= self.ban_frequency and
                entry["是否添加黑名单"] == "False" and self._is_public_ip(ip) and not self._is_blocked(ip)):
                self._block_ip(ip)

    def _daily_summary(self):
        while not self.stop_event.is_set():
            now = datetime.datetime.now()
            next_midnight = (now + datetime.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            wait = (next_midnight - now).total_seconds()
            if wait > 0:
                self.stop_event.wait(wait)
            if self.stop_event.is_set():
                break
            self._send_failure_summary()

    def _send_failure_summary(self):
        with self.lock:
            if not os.path.exists(FAILURE_JSON_FILE):
                return
            jdata = self._load_json()
            ip_dict = jdata.get("失败的IP地址", {})
            if not ip_dict:
                return
            date_str = datetime.date.today().strftime("%Y-%m-%d")
            subject = f"登录失败每日汇总 - {date_str}"
            body = f"以下是 {date_str} 的登录失败汇总，按 IP 统计：\n\n"
            for ip, stats in ip_dict.items():
                body += f"IP: {ip}\n失败总次数: {stats['失败总次数']}\n黑名单状态: {'是' if stats['是否添加黑名单']=='True' else '否'}\n"
                records = stats.get("登陆记录", [])[-10:]
                if len(records) > 10:
                    body += f"（仅显示最近10条，共{len(stats['登陆记录'])}条）\n"
                for rec in records:
                    body += f"  - {rec['时间']} {rec['用户名']} 方式: {rec['方式']}\n"
                body += "\n"
            body += "（Columba 自动发送）"
            if _send_email_raw(self.smtp_cfg, subject, body):
                log("每日失败汇总邮件发送成功")
                self._save_json({"失败的IP地址": {}})
            else:
                log("每日失败汇总邮件发送失败，保留记录")

    def _start_daily_task(self):
        threading.Thread(target=self._daily_summary, daemon=True).start()

    def shutdown(self):
        self.stop_event.set()

    # ---------- 动态更新配置 ----------
    def update_config(self, smtp_cfg, msg_cfg, ban_frequency):
        """外部调用，更新邮件配置和封禁频率"""
        self.smtp_cfg = smtp_cfg
        self.msg_cfg = msg_cfg
        self.ban_frequency = ban_frequency
        log("FailureCollector 配置已更新")

# ========== 托盘应用 ==========
class TrayApp:
    def __init__(self):
        # 加载配置（首次启动，失败则退出）
        self.smtp, self.msg, self.allowed_types, self.ban_freq = load_config()
        self.collector = FailureCollector(self.smtp, self.msg, self.ban_freq)
        self.monitor = None
        self.success_cooldown = 60
        self.last_success = {}

    def send_success(self, data):
        key = (data.get("username"), data.get("source_ip"))
        now = time.time()
        if self.last_success.get(key, 0) > now - self.success_cooldown:
            log(f"冷却中，跳过通知: {data['username']} ({data.get('source_ip')})")
            return
        self.last_success[key] = now
        send_mail(self.smtp, self.msg, data)

    def handle_failure(self, data):
        self.collector.log_failure(data)

    def test_mail(self):
        log("测试邮件")
        send_mail(self.smtp, self.msg, test=True)

    def edit_config(self):
        """打开配置文件（记事本），并立即重新加载（类似2.1.py的行为）"""
        if not os.path.exists(CONFIG_FILE):
            # 若不存在，创建一个默认模板
            default = {
                "SMTP": {"server": "smtp.example.com", "port": 587, "username": "", "password": "",
                         "use_tls": True, "from_addr": "", "to_addr": ""},
                "SETTINGS": {"ban_frequency": 5, "logon_types": "2,3,7,10"},
                "MESSAGE": {"subject_success": "Columba 登录通知 - 成功",
                            "body_success": "用户 {username} 在计算机 {computer} 上登录成功\n登录类型: {logon_type_desc}\n时间: {time}\n来源 IP: {source_ip}\n进程: {process_name}"}
            }
            try:
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(default, f, indent=2, ensure_ascii=False)
                log("已创建默认配置文件模板: " + CONFIG_FILE)
            except Exception as e:
                log(f"写入默认模板时异常: {e}")
                show_error(f"无法创建配置文件模板：{e}")
                return
        # 打开记事本编辑
        subprocess.Popen(["notepad.exe", CONFIG_FILE], creationflags=subprocess.CREATE_NO_WINDOW)
        # 立即重新加载配置（注意：此时用户可能还没保存，但行为与2.1.py一致）
        self.reload_config()

    def reload_config(self):
        """重新加载配置文件，并更新所有相关模块"""
        try:
            new_smtp, new_msg, new_allowed_types, new_ban_freq = load_config(exit_on_error=False)
            # 更新自身属性
            self.smtp = new_smtp
            self.msg = new_msg
            self.allowed_types = new_allowed_types
            self.ban_freq = new_ban_freq

            # 更新监听器的允许类型
            if self.monitor:
                self.monitor.allowed_logon_types = new_allowed_types

            # 更新失败收集器的配置
            self.collector.update_config(new_smtp, new_msg, new_ban_freq)

            # 清空成功登录的冷却缓存（可选，避免旧配置影响）
            self.last_success.clear()

            log("配置已重新加载，新配置已生效")
        except Exception as e:
            log(f"重新加载配置失败: {e}")
            show_error(f"配置文件错误，无法重新加载：{e}\n请检查文件格式。")

    def view_log(self):
        if os.path.exists(LOG_FILE):
            subprocess.Popen(["notepad.exe", LOG_FILE], creationflags=subprocess.CREATE_NO_WINDOW)

    def view_failure(self):
        if os.path.exists(FAILURE_JSON_FILE):
            subprocess.Popen(["notepad.exe", FAILURE_JSON_FILE], creationflags=subprocess.CREATE_NO_WINDOW)

    def on_quit(self, icon):
        if self.monitor:
            self.monitor.stop()
        self.collector.shutdown()
        icon.stop()
        log("程序退出")
        os._exit(0)

    def run(self):
        self.monitor = LoginMonitor(self.send_success, self.handle_failure, self.allowed_types)
        threading.Thread(target=self.monitor.run, daemon=True).start()

        # 加载图标
        try:
            image = Image.open(ICON_FILE) if os.path.exists(ICON_FILE) else Image.new('RGBA', (64, 64), (0,0,0,0))
        except Exception:
            log("警告：图标加载失败，使用空白图标")
            image = Image.new('RGBA', (64, 64), (0,0,0,0))

        menu = pystray.Menu(
            pystray.MenuItem("测试邮件", self.test_mail),
            pystray.MenuItem("编辑配置", self.edit_config),   # 手动编辑并重载
            pystray.MenuItem("查看日志", self.view_log),
            pystray.MenuItem("查看失败登录记录", self.view_failure),
            pystray.MenuItem("退出", self.on_quit)
        )
        icon = pystray.Icon("LoginNotifier", image, "Columba", menu)
        log("程序已启动，托盘图标显示")
        icon.run()

def main():
    if not is_admin():
        log("请求管理员权限...")
        run_as_admin()
        return
    log("以管理员身份运行")
    try:
        TrayApp().run()
    except Exception as e:
        log(f"程序启动失败: {e}")
        import traceback
        log(traceback.format_exc())
        show_error(f"程序启动失败：{e}")
        input("按回车键退出...")

if __name__ == "__main__":
    main()