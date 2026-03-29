import os
import sys
import threading
import time
import smtplib
import configparser
import ctypes
import subprocess
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

# 常量
CONFIG_FILE = "config.ini"
LOG_FILE = "login_notifier.log"
ICON_FILE = "columba.ico"

# ---------- 日志配置 ----------
# 使用 RotatingFileHandler，单个文件最大 3MB，backupCount=0 表示不保留备份（达到大小后清空）
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
    """显示错误消息框"""
    ctypes.windll.user32.MessageBoxW(0, msg, "错误", 0x10)

# ---------- 权限检查 ----------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """请求以管理员身份运行，失败时弹出提示框"""
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

        if ret > 32:   # 成功启动新进程
            log("提权成功，新进程已启动")
        else:
            error_code = ret
            show_error(f"提权失败 (错误码: {error_code})，请手动以管理员身份运行。")
            log(f"提权失败，ShellExecuteW 返回 {error_code}")
    except Exception as e:
        log(f"提权过程异常: {e}")
        show_error(f"提权异常: {e}\n请手动以管理员身份运行。")
    sys.exit(0)   # 当前进程退出

# ---------- 配置管理 ----------
def check_config():
    """检查配置文件是否存在，不存在则报错退出"""
    if not os.path.exists(CONFIG_FILE):
        log(f"错误：配置文件 {CONFIG_FILE} 不存在！")
        sys.exit(1)

def load_config():
    check_config()
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE, encoding='utf-8')
    smtp = config["SMTP"]
    msg = config["MESSAGE"]
    allowed_types_str = config.get("FILTER", "logon_types", fallback="2,7,10")
    allowed_types = set()
    for t in allowed_types_str.split(','):
        t = t.strip()
        if t.isdigit():
            allowed_types.add(int(t))
    return smtp, msg, allowed_types

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

def send_mail(smtp_cfg, msg_cfg, event_data, test=False):
    try:
        msg = MIMEMultipart()
        msg["From"] = formataddr(("Columba", smtp_cfg["from_addr"]))
        msg["To"] = smtp_cfg["to_addr"]

        if test:
            msg["Subject"] = Header("测试邮件 - Columba 通知", "utf-8")
            body = "这是一封测试邮件，您的邮件配置正常。"
        else:
            if "logon_type" in event_data:
                event_data["logon_type_desc"] = get_logon_type_desc(int(event_data["logon_type"]))
            else:
                event_data["logon_type_desc"] = "未知"
            if event_data["event_type"] == "success":
                subject = msg_cfg["subject_success"]
                body = msg_cfg["body_success"].format(**event_data)
            else:
                subject = msg_cfg["subject_failure"]
                body = msg_cfg["body_failure"].format(**event_data)
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
        log("邮件发送成功")
        return True
    except Exception as e:
        log(f"邮件发送失败: {e}")
        return False

# ---------- 安全日志监听 ----------
class LoginMonitor:
    def __init__(self, callback, allowed_logon_types):
        self.callback = callback
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

            if event.EventID == 4624:
                logon_type = self._parse_logon_type(strings, 8)
                if logon_type is None:
                    log(f"无法解析登录类型: {strings}")
                    return None

                if self.allowed_logon_types and logon_type not in self.allowed_logon_types:
                    log(f"忽略登录类型 {logon_type}，不在允许列表 {self.allowed_logon_types}")
                    return None

                return {
                    "event_type": "success",
                    "logon_type": logon_type,
                    "username": strings[5] if len(strings) > 5 else "?",
                    "domain": strings[6] if len(strings) > 6 else "?",
                    "process_name": strings[17] if len(strings) > 17 else "?",
                    "source_ip": strings[18] if len(strings) > 18 else "?",
                    "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                    "computer": os.environ.get("COMPUTERNAME", "Unknown"),
                }

            elif event.EventID == 4625:
                logon_type = self._parse_logon_type(strings, 10)
                if logon_type is None:
                    log(f"无法解析失败事件的登录类型: {strings}")
                    return None

                status = strings[7] if len(strings) > 7 else "?"
                substatus = strings[9] if len(strings) > 9 else "?"
                failure_reason = f"状态码: {status}, 子状态: {substatus}"

                return {
                    "event_type": "failure",
                    "logon_type": logon_type,
                    "username": strings[5] if len(strings) > 5 else "?",
                    "domain": strings[6] if len(strings) > 6 else "?",
                    "failure_reason": failure_reason,
                    "source_ip": strings[19] if len(strings) > 19 else "?",
                    "time": event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
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
                        self.callback(data)
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

# ---------- 托盘应用 ----------
class TrayApp:
    def __init__(self):
        self.smtp_cfg, self.msg_cfg, self.allowed_types = load_config()
        self.monitor = None
        self.thread = None

    def send_notification(self, data):
        send_mail(self.smtp_cfg, self.msg_cfg, data)

    def test_mail(self):
        log("测试邮件")
        send_mail(self.smtp_cfg, self.msg_cfg, None, test=True)

    def edit_config(self):
        if os.path.exists(CONFIG_FILE):
            subprocess.Popen(
                ["notepad.exe", CONFIG_FILE],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        # 重新加载配置，使更改立即生效
        self.smtp_cfg, self.msg_cfg, self.allowed_types = load_config()
        if self.monitor:
            self.monitor.allowed_logon_types = self.allowed_types
        log("配置已更新")

    def view_log(self):
        if os.path.exists(LOG_FILE):
            subprocess.Popen(
                ["notepad.exe", LOG_FILE],
                creationflags=subprocess.CREATE_NO_WINDOW
            )

    def on_quit(self, icon):
        if self.monitor:
            self.monitor.stop()
        icon.stop()
        log("程序退出")
        os._exit(0)

    def run(self):
        self.monitor = LoginMonitor(self.send_notification, self.allowed_types)
        self.thread = threading.Thread(target=self.monitor.run, daemon=True)
        self.thread.start()

        # 加载自定义图标，失败则报错退出
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
            return   # run_as_admin 会退出当前进程

        log("以管理员身份运行")
        app = TrayApp()
        app.run()
    except Exception as e:
        # 其他异常（如配置文件缺失、图标缺失等）仅记录日志，不弹窗
        log(f"程序启动失败: {e}")
        import traceback
        log(traceback.format_exc())
        # 如果是在命令行运行，暂停一下让用户看到错误信息
        input("按回车键退出...")

if __name__ == "__main__":
    main()
