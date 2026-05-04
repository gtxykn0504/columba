import os
import sys
import threading
import time
import smtplib
import configparser
import ctypes
import subprocess
import datetime
import json
import ipaddress
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
import logging
from logging.handlers import RotatingFileHandler
import pythoncom
import win32evtlog
import pystray
from PIL import Image

# ---------- 常量 ----------
CONFIG_FILE = "config.ini"
LOG_FILE = "login_notifier.log"
FAILURE_JSON_FILE = "failure_login.json"
ICON_FILE = "columba.ico"

# ---------- 日志配置 ----------
handler = RotatingFileHandler(LOG_FILE, maxBytes=3*1024*1024, backupCount=0, encoding='utf-8')
handler.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[handler, console_handler]
)
log = logging.info

# ---------- 工具函数 ----------
def show_error(msg):
    ctypes.windll.user32.MessageBoxW(0, msg, "错误", 0x10)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    try:
        if getattr(sys, 'frozen', False):
            script = sys.argv[0]
            params = " ".join(sys.argv[1:])
        else:
            script = sys.executable
            params = f'"{sys.argv[0]}" ' + " ".join(sys.argv[1:])

        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", script, params, None, 1
        )
        if ret > 32:
            log("提权成功，新进程已启动")
        else:
            show_error(f"提权失败 (错误码: {ret})，请手动以管理员身份运行。")
            log(f"提权失败，ShellExecuteW 返回 {ret}")
    except Exception as e:
        log(f"提权过程异常: {e}")
        show_error(f"提权异常: {e}\n请手动以管理员身份运行。")
    sys.exit(0)

# ---------- 配置管理 ----------
def check_config():
    if not os.path.exists(CONFIG_FILE):
        log(f"错误：配置文件 {CONFIG_FILE} 不存在！")
        sys.exit(1)

def load_config():
    check_config()
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE, encoding='utf-8-sig')
    smtp = config["SMTP"]
    msg = config["MESSAGE"]      # 只保留成功邮件的配置，不再读取失败邮件相关字段
    allowed_types_str = config.get("SETTINGS", "logon_types")
    allowed_types = set()
    for t in allowed_types_str.split(','):
        t = t.strip()
        if t.isdigit():
            allowed_types.add(int(t))
    ban_frequency = config.getint("SETTINGS", "ban_frequency")
    return smtp, msg, allowed_types, ban_frequency

def get_logon_type_desc(logon_type):
    desc_map = {
        2: "交互式登录 (Interactive)",
        3: "网络登录 (Network)",
        4: "批处理登录 (Batch)",
        5: "服务登录 (Service)",
        7: "解锁登录 (Unlock)",
        8: "网络明文登录 (Network Cleartext)",
        9: "新凭证登录 (New Credentials)",
        10: "远程交互式登录 (RemoteInteractive)",
        11: "缓存交互式登录 (CachedInteractive)",
    }
    return desc_map.get(logon_type, f"未知类型 ({logon_type})")

# ---------- 邮件发送（仅用于成功通知和测试）----------
def _send_email_raw(smtp_cfg, subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"] = formataddr(("Columba", smtp_cfg["from_addr"]))
        msg["To"] = smtp_cfg["to_addr"]
        msg["Subject"] = Header(subject, "utf-8")
        msg.attach(MIMEText(body, "plain", "utf-8"))

        if smtp_cfg.getboolean("use_tls"):
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

def send_mail(smtp_cfg, msg_cfg, event_data, test=False):
    if test:
        subject = "测试邮件 - Columba 通知"
        body = "这是一封测试邮件，您的邮件配置正常。"
    else:
        # 仅处理成功登录通知（失败已改为每日汇总）
        if "logon_type" in event_data:
            event_data["logon_type_desc"] = get_logon_type_desc(int(event_data["logon_type"]))
        else:
            event_data["logon_type_desc"] = "未知"
        subject = msg_cfg["subject_success"]
        body = msg_cfg["body_success"].format(**event_data)

    success = _send_email_raw(smtp_cfg, subject, body)
    if success:
        log("邮件发送成功")
    return success

# ---------- 安全日志监听 ----------
class LoginMonitor:
    def __init__(self, success_callback, failure_callback, allowed_logon_types):
        self.success_callback = success_callback
        self.failure_callback = failure_callback
        self.running = True
        self.processed = {}
        self.allowed_logon_types = allowed_logon_types

    def _parse_logon_type(self, strings, index):
        logon_type = None
        if len(strings) > index:
            try:
                logon_type = int(strings[index])
            except ValueError:
                for i, s in enumerate(strings):
                    if s.isdigit():
                        logon_type = int(s)
                        log(f"登录类型在索引 {i} 找到: {logon_type}")
                        break
        return logon_type

    def _parse_event(self, event):
        try:
            strings = event.StringInserts
            if not strings:
                return None
            time_formatted = event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S") + f",{event.TimeGenerated.microsecond // 1000:03d}"

            if event.EventID == 4624:
                logon_type = self._parse_logon_type(strings, 8)
                if logon_type is None:
                    log(f"无法解析登录类型: {strings}")
                    return None
                if self.allowed_logon_types and logon_type not in self.allowed_logon_types:
                    log(f"忽略登录类型 {logon_type}")
                    return None
                return {
                    "event_type": "success",
                    "logon_type": logon_type,
                    "logon_type_desc": get_logon_type_desc(logon_type),
                    "username": strings[5] if len(strings) > 5 else "?",
                    "domain": strings[6] if len(strings) > 6 else "?",
                    "process_name": strings[17] if len(strings) > 17 else "?",
                    "source_ip": strings[18] if len(strings) > 18 else "?",
                    "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                    "time_formatted": time_formatted,
                    "computer": os.environ.get("COMPUTERNAME", "Unknown"),
                }
            elif event.EventID == 4625:
                logon_type = self._parse_logon_type(strings, 10)
                if logon_type is None:
                    log(f"无法解析失败事件登录类型: {strings}")
                    return None
                status = strings[7] if len(strings) > 7 else "?"
                substatus = strings[9] if len(strings) > 9 else "?"
                failure_reason = f"状态码: {status}, 子状态: {substatus}"
                return {
                    "event_type": "failure",
                    "logon_type": logon_type,
                    "logon_type_desc": get_logon_type_desc(logon_type),
                    "username": strings[5] if len(strings) > 5 else "?",
                    "domain": strings[6] if len(strings) > 6 else "?",
                    "failure_reason": failure_reason,
                    "source_ip": strings[19] if len(strings) > 19 else "?",
                    "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                    "time_formatted": time_formatted,
                    "computer": os.environ.get("COMPUTERNAME", "Unknown"),
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
                for event in events:
                    if event.EventID not in (4624, 4625):
                        continue
                    if event.RecordNumber in self.processed:
                        continue
                    self.processed[event.RecordNumber] = None
                    if len(self.processed) > 1000:
                        self.processed.pop(next(iter(self.processed)))
                    data = self._parse_event(event)
                    if data:
                        log(f"检测到事件 {event.EventID}: {data['username']} (类型 {data.get('logon_type')})")
                        if data["event_type"] == "success":
                            self.success_callback(data)
                        else:
                            self.failure_callback(data)
                win32evtlog.CloseEventLog(hand)
                hand = None
            except Exception as e:
                log(f"监听出错: {e}")
                if hand:
                    try:
                        win32evtlog.CloseEventLog(hand)
                    except:
                        pass
                time.sleep(5)
            else:
                time.sleep(2)
        pythoncom.CoUninitialize()

    def stop(self):
        self.running = False

# ---------- 失败登录记录与拦截 ----------
class FailureCollector:
    def __init__(self, smtp_cfg, msg_cfg, ban_frequency):
        self.smtp_cfg = smtp_cfg
        self.msg_cfg = msg_cfg
        self.ban_frequency = ban_frequency
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self._start_daily_task()

    def _load_json(self):
        if os.path.exists(FAILURE_JSON_FILE):
            try:
                with open(FAILURE_JSON_FILE, "r", encoding="utf-8") as f:
                    content = f.read()
                    if content.strip():
                        return json.loads(content)
            except Exception:
                pass
        return {"失败的IP地址": {}}

    def _save_json(self, data):
        try:
            with open(FAILURE_JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log(f"[JSON] 保存失败: {e}")

    def _is_public_ip(self, ip_str):
        try:
            addr = ipaddress.ip_address(ip_str)
            return not addr.is_private and not addr.is_loopback
        except ValueError:
            return False

    def _is_blocked(self, ip_str):
        rule_name = f"Columba Block {ip_str}"
        command = f'netsh advfirewall firewall show rule name="{rule_name}"'
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = result.stdout + result.stderr
            # 规则存在时输出必定包含“规则名称:”或“Rule Name:”字段
            return "规则名称:" in output or "Rule Name:" in output
        except Exception:
            return False

    def _block_ip(self, ip_str):
        rule_name = f"Columba Block {ip_str}"
        command = (
            f'netsh advfirewall firewall add rule '
            f'name="{rule_name}" dir=in action=block '
            f'remoteip={ip_str}'
        )
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode == 0:
                log(f"[防火墙] 成功封禁 IP: {ip_str} (规则名: {rule_name})")
                with self.lock:
                    jdata = self._load_json()
                    ip_entry = jdata.get("失败的IP地址", {}).get(ip_str)
                    if ip_entry:
                        ip_entry["是否添加黑名单"] = "True"
                        self._save_json(jdata)
            else:
                log(f"[防火墙] 封禁 IP {ip_str} 失败: {result.stderr.strip()}")
        except Exception as e:
            log(f"[防火墙] 执行封禁命令异常 (IP: {ip_str}): {e}")

    def log_failure(self, data):
        ip = data.get("source_ip", "?")
        if ip == "?" or ip == "":
            return
        with self.lock:
            jdata = self._load_json()
            ip_dict = jdata.setdefault("失败的IP地址", {})
            ip_entry = ip_dict.setdefault(ip, {
                "失败总次数": "0",
                "是否添加黑名单": "False",
                "登陆记录": []
            })
            count = int(ip_entry["失败总次数"]) + 1
            ip_entry["失败总次数"] = str(count)
            # 记录中加入用户名
            record = {
                "时间": data["time_formatted"],
                "用户名": data.get("username", "?"),
                "方式": data.get("logon_type_desc", "未知")
            }
            ip_entry["登陆记录"].append(record)
            self._save_json(jdata)
            current_count = count
            already_banned = ip_entry.get("是否添加黑名单", "False") == "True"

        if (self.ban_frequency > 0 and
            current_count >= self.ban_frequency and
            not already_banned and
            self._is_public_ip(ip) and
            not self._is_blocked(ip)):
            self._block_ip(ip)

    # ---------- 每日汇总 ----------
    def _get_next_midnight(self):
        now = datetime.datetime.now()
        tomorrow = now.date() + datetime.timedelta(days=1)
        return datetime.datetime.combine(tomorrow, datetime.time(0, 0, 0))

    def _daily_summary(self):
        while not self.stop_event.is_set():
            next_run = self._get_next_midnight()
            now = datetime.datetime.now()
            wait_seconds = (next_run - now).total_seconds()
            if wait_seconds > 0:
                self.stop_event.wait(wait_seconds)
            if self.stop_event.is_set():
                break
            self._send_failure_summary()

    def _send_failure_summary(self):
        with self.lock:
            if not os.path.exists(FAILURE_JSON_FILE):
                return
            try:
                jdata = self._load_json()
            except Exception:
                return
            ip_dict = jdata.get("失败的IP地址", {})
            if not ip_dict:
                return

            date_str = datetime.date.today().strftime("%Y-%m-%d")
            subject = f"登录失败每日汇总 - {date_str}"
            body = f"以下是 {date_str} 的登录失败汇总，按 IP 统计：\n\n"

            for ip, stats in ip_dict.items():
                ban_status = "是" if stats.get("是否添加黑名单", "False") == "True" else "否"
                body += f"IP: {ip}\n"
                body += f"失败总次数: {stats['失败总次数']}\n"
                body += f"黑名单状态: {ban_status}\n"
                records = stats.get("登陆记录", [])
                show_records = records[-10:]
                if len(records) > 10:
                    body += f"（仅显示最近 {len(show_records)} 条，共 {len(records)} 条）\n"
                for rec in show_records:
                    # 格式: 时间 用户名 方式: ...
                    user = rec.get("用户名", "?")
                    body += f"  - {rec['时间']} {user} 方式: {rec['方式']}\n"
                body += "\n"

            body += "（Columba 自动发送）"

            success = _send_email_raw(self.smtp_cfg, subject, body)
            if success:
                log("每日失败汇总邮件发送成功")
                self._save_json({"失败的IP地址": {}})
            else:
                log("每日失败汇总邮件发送失败，将保留记录等待下次重试")

    def _start_daily_task(self):
        t = threading.Thread(target=self._daily_summary, daemon=True)
        t.start()

    def shutdown(self):
        self.stop_event.set()

# ---------- 托盘应用 ----------
class TrayApp:
    def __init__(self):
        self.smtp_cfg, self.msg_cfg, self.allowed_types, self.ban_frequency = load_config()
        self.failure_collector = FailureCollector(self.smtp_cfg, self.msg_cfg, self.ban_frequency)
        self.monitor = None
        self.thread = None
        self.success_cooldown = 60          # 成功通知冷却秒数
        self.last_success_time = {}         # key: (username, ip) -> timestamp

    def send_success_notification(self, data):
        key = (data.get("username"), data.get("source_ip"))
        now = time.time()
        last = self.last_success_time.get(key)
        if last and now - last < self.success_cooldown:
            log(f"成功登录冷却中，跳过通知: {data['username']} (Ip {data.get('source_ip')})")
            return
        self.last_success_time[key] = now
        send_mail(self.smtp_cfg, self.msg_cfg, data)

    def handle_failure_event(self, data):
        self.failure_collector.log_failure(data)

    def test_mail(self):
        log("测试邮件")
        send_mail(self.smtp_cfg, self.msg_cfg, None, test=True)

    def edit_config(self):
        if os.path.exists(CONFIG_FILE):
            subprocess.Popen(
                ["notepad.exe", CONFIG_FILE],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        self.smtp_cfg, self.msg_cfg, self.allowed_types, self.ban_frequency = load_config()
        if self.monitor:
            self.monitor.allowed_logon_types = self.allowed_types
        self.failure_collector.smtp_cfg = self.smtp_cfg
        self.failure_collector.msg_cfg = self.msg_cfg
        self.failure_collector.ban_frequency = self.ban_frequency
        self.last_success_time.clear()
        log("配置已更新")

    def view_log(self):
        if os.path.exists(LOG_FILE):
            subprocess.Popen(
                ["notepad.exe", LOG_FILE],
                creationflags=subprocess.CREATE_NO_WINDOW
            )

    def view_failure_log(self):
        if os.path.exists(FAILURE_JSON_FILE):
            subprocess.Popen(
                ["notepad.exe", FAILURE_JSON_FILE],
                creationflags=subprocess.CREATE_NO_WINDOW
            )

    def on_quit(self, icon):
        if self.monitor:
            self.monitor.stop()
        self.failure_collector.shutdown()
        icon.stop()
        log("程序退出")
        os._exit(0)

    def run(self):
        self.monitor = LoginMonitor(self.send_success_notification, self.handle_failure_event, self.allowed_types)
        self.thread = threading.Thread(target=self.monitor.run, daemon=True)
        self.thread.start()

        if not os.path.exists(ICON_FILE):
            log(f"错误：图标文件 {ICON_FILE} 不存在！")
            sys.exit(1)
        try:
            image = Image.open(ICON_FILE)
        except Exception as e:
            log(f"错误：加载图标失败 - {e}")
            sys.exit(1)

        menu = pystray.Menu(
            pystray.MenuItem("测试邮件", self.test_mail),
            pystray.MenuItem("编辑配置", self.edit_config),
            pystray.MenuItem("查看日志", self.view_log),
            pystray.MenuItem("查看失败登录记录", self.view_failure_log),
            pystray.MenuItem("退出", self.on_quit)
        )
        icon = pystray.Icon("LoginNotifier", image, "Columba", menu)
        log("程序已启动，托盘图标显示")
        icon.run()

def main():
    try:
        if not is_admin():
            log("当前非管理员权限，正在请求提权...")
            run_as_admin()
            return
        log("以管理员身份运行")
        app = TrayApp()
        app.run()
    except Exception as e:
        log(f"程序启动失败: {e}")
        import traceback
        log(traceback.format_exc())
        input("按回车键退出...")

if __name__ == "__main__":
    main()
