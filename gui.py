"""
ProXDefend — Desktop GUI
Style: Clean dark theme matching the original browser UI
Dark background · Rounded cards · Top navbar · Hero section · Segoe UI typography
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading, time, os, hashlib, psutil, math, re, subprocess, ipaddress
import smtplib, json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from collections import deque

# Email settings file path
EMAIL_CFG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'email_config.json')

# System tray — built with pure ctypes (Windows built-in, no pip install needed)
import ctypes
import ctypes.wintypes
import struct

# Windows API constants
WM_USER        = 0x0400
WM_TRAYICON    = WM_USER + 20
NIM_ADD        = 0x00000000
NIM_DELETE     = 0x00000002
NIM_MODIFY     = 0x00000001
NIF_ICON       = 0x00000001
NIF_MESSAGE    = 0x00000002
NIF_TIP        = 0x00000004
NIF_INFO       = 0x00000010
NIIF_INFO      = 0x00000001
NIIF_WARNING   = 0x00000002
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONUP     = 0x0205
WM_DESTROY       = 0x0002
WS_OVERLAPPED    = 0x00000000
CS_HREDRAW       = 0x0002
CS_VREDRAW       = 0x0001
IDI_APPLICATION  = 32512
IDC_ARROW        = 32512
WM_COMMAND       = 0x0111
TPM_LEFTALIGN    = 0x0000
TPM_RETURNCMD    = 0x0100
MF_STRING        = 0x00000000
MF_SEPARATOR     = 0x00000800
MF_GRAYED        = 0x00000001

# ═══════════════════════════════════════════════════════════════════════════════
#  COLOUR TOKENS  (mirrors the original browser dark theme exactly)
# ═══════════════════════════════════════════════════════════════════════════════
BG          = "#0d1117"   # page background
CARD        = "#161b22"   # card / navbar surface
CARD2       = "#1c2128"   # slightly lighter card hover
BORDER      = "#30363d"   # subtle border / divider
TEXT        = "#e6edf3"   # primary text
MUTED       = "#8b949e"   # secondary / caption text
ACCENT      = "#58a6ff"   # blue accent (matches original)
ACCENT_DIM  = "#1f4068"   # accent dimmed background
SUCCESS     = "#3fb950"   # green
WARNING     = "#d29922"   # amber
DANGER      = "#f85149"   # red
BTN_BG      = "#21262d"   # outline button background
BTN_BORDER  = "#f0f6fc"   # outline button border/text

F           = "Segoe UI"  # primary font family

# ═══════════════════════════════════════════════════════════════════════════════
#  BACKEND LOGIC
# ═══════════════════════════════════════════════════════════════════════════════
SUSPICIOUS_KEYWORDS = [
    "powershell","cmd","nc","ncat","mimikatz","evil","hack","exploit",
    "payload","trojan","malware","sh -i","/dev/tcp","reverse shell",
    "bind shell","netcat","socat","bash -i",">& /dev/tcp","python -c",
    "perl -e","ruby -rsocket","php -r","fsockopen","socket.connect",
    "exec('/bin/bash')","system('/bin/bash')","ProcessBuilder","pty.spawn",
    "/bin/sh","0>&1"
]
SUSPICIOUS_PORTS = [
    4444,1337,6666,12345,5555,22,23,3389,5900,5800,5000,
    1433,1434,3306,5432,27017,80,443,8080,8443,21,20,69,
    25,465,587,53,135,139,445,1080,3128,8081,8888
]
SUSPICIOUS_IP_RANGES = [
    '192.168.0.0/16','10.0.0.0/8','172.16.0.0/12','169.254.0.0/16','127.0.0.0/8'
]
WINDOWS_SYSTEM_PROCESSES = {
    'svchost.exe','lsass.exe','csrss.exe','winlogon.exe','services.exe',
    'smss.exe','explorer.exe','spoolsv.exe','wininit.exe','fontdrvhost.exe',
    'dwm.exe','taskmgr.exe','RuntimeBroker.exe','WUDFHost.exe',
    'cmd.exe','msedgewebview2.exe','powershell.exe'
}
CRITICAL_SYSTEM_PROCESSES = {
    'System','Registry','smss.exe','csrss.exe','wininit.exe',
    'services.exe','lsass.exe','winlogon.exe','explorer.exe','svchost.exe'
}
KEYWORD_FIX = {
    "powershell": "Disable unnecessary PowerShell access. Check for malicious scripts.",
    "cmd":        "Restrict cmd.exe via group policies if abuse detected.",
    "nc":         "Possible reverse shell. Kill immediately and scan for backdoors.",
    "mimikatz":   "Password dumper detected! Change all credentials immediately.",
    "exploit":    "Exploit tool detected. Patch system vulnerabilities now.",
    "malware":    "Malware detected. Isolate device and run full antivirus scan.",
}
WHITELIST_PORTS = {5000,3000,8000,8080,22,443,80}
WHITELIST_IPS   = {'127.0.0.1','localhost'}

# Only HIGH-CONFIDENCE patterns that are genuinely rare in clean files.
# Overly broad patterns (eval, exec, connect, system, socket) are removed
# because they appear in virtually every Python/JS/HTML file and cause false positives.
MALWARE_PATTERNS = {
    # Shellcode: long NOP sled or INT3 breakpoint chains — never in clean files
    'shellcode':             rb'\x90{20,}|\xCC{20,}',
    # Encoded PowerShell — base64 payload after -enc/-EncodedCommand flag
    'powershell_encoded':    rb'(?i)powershell[^|&;\n]{0,60}-e(?:nc|ncodedcommand)\s+[A-Za-z0-9+/]{40,}={0,2}',
    # Command shell execution via cmd.exe/powershell with /c flag
    'suspicious_commands':   rb'(?i)(cmd\.exe|powershell\.exe|wscript\.exe|mshta\.exe)\s+/c\s+',
    # Win32 memory-injection API names — only in compiled binaries doing injection
    'suspicious_functions':  rb'(CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|NtUnmapViewOfSection)',
    # Exact known C2/RAT ports in connection strings
    'suspicious_ports':      rb':(4444|1337|6666|12345|5555)\b',
    # VBA macro auto-execution triggers — specific to Office documents
    'suspicious_macros':     rb'(?i)(AutoOpen|Document_Open|Workbook_Open|Auto_Open)',
    # Reverse shell one-liners — very specific syntax
    'reverse_shell':         rb'(?i)(sh\s+-i\s*>[>&]\s*/dev/tcp/\d|bash\s+-i\s*>[>&]\s*/dev/tcp/\d|nc\s+-e\s+/bin/(?:sh|bash)|/bin/sh\s+-i)',
    # Anti-debug API calls — only in compiled executables trying to evade analysis
    'suspicious_antidebug':  rb'(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)',
    # Registry persistence keys — specific key names used for malware persistence
    'suspicious_persistence':rb'(?i)(HKCU|HKLM)\\[^\n]{0,80}(Run|RunOnce|Winlogon\\Shell)',
    # Mimikatz and known credential-dumping strings
    'credential_dumping':    rb'(?i)(sekurlsa|lsadump|mimikatz|wce\.exe|fgdump)',
}

def get_file_hash(path):
    try:
        with open(path,'rb') as f: return hashlib.sha256(f.read()).hexdigest()
    except: return None

def calculate_entropy(data):
    if not data: return 0
    e = 0
    for x in range(256):
        p = data.count(bytes([x])) / len(data)
        if p > 0: e += -p * math.log2(p)
    return e

def scan_file(path):
    r = {"verdict":"Unknown","patterns":[],"details":[],"hash":None,"file_type":"Unknown","file_size":"0 MB"}
    try:
        r["file_size"] = f"{os.path.getsize(path)/(1024*1024):.2f} MB"
        r["hash"] = get_file_hash(path)
        try:
            import magic; r["file_type"] = magic.from_file(path, mime=True)
        except:
            r["file_type"] = os.path.splitext(path)[1].lower() or "unknown"

        found, details = [], []

        with open(path,'rb') as f: content = f.read(5*1024*1024)

        # ── Entropy check ────────────────────────────────────────────────────
        # Only flag high entropy for executable/binary types.
        # Archives (zip, pdf, png, jpg) are naturally high-entropy — skip them.
        file_type = r["file_type"]
        low_entropy_types = (
            'application/zip','application/gzip','application/x-7z-compressed',
            'application/x-rar','application/pdf','image/','audio/','video/',
            'application/vnd.openxmlformats','application/vnd.ms-',
        )
        skip_entropy = any(file_type.startswith(t) for t in low_entropy_types)
        if not skip_entropy:
            entropy = calculate_entropy(content)
            if entropy > 7.5:   # raised from 7.0 → 7.5 to reduce false positives
                details.append(f"High entropy ({entropy:.2f}) — possible obfuscation/encryption")
                found.append("high_entropy")

        # ── Binary pattern scan (runs on all file types) ─────────────────────
        for pname, pattern in MALWARE_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                found.append(pname)
                details.append(f"Suspicious pattern detected: {pname.replace('_',' ')}")

        # ── Keyword scan — TEXT files only ───────────────────────────────────
        # Skip binary/compiled/archive/image files to avoid matching garbage bytes.
        TEXT_TYPES = (
            'text/', 'application/javascript', 'application/json',
            'application/xml', 'application/x-sh', 'application/x-python',
            'application/x-httpd-php', 'application/x-perl',
        )
        TEXT_EXTENSIONS = {
            '.txt','.py','.js','.php','.sh','.bat','.ps1','.vbs',
            '.html','.htm','.xml','.json','.csv','.log','.cfg','.ini',
            '.rb','.pl','.java','.c','.cpp','.cs','.ts',
        }
        ext = os.path.splitext(path)[1].lower()
        is_text = (
            any(file_type.startswith(t) for t in TEXT_TYPES) or
            ext in TEXT_EXTENSIONS
        )
        if is_text:
            # High-confidence keywords — require word-boundary or full-phrase match
            HIGH_CONF_KEYWORDS = [
                "mimikatz", "meterpreter", "reverse shell", "bind shell",
                ">& /dev/tcp", "/dev/tcp", "powershell -enc",
                "powershell -nop", "IEX(", "IEX (", "Invoke-Expression",
                "exec('/bin/bash')", "exec('/bin/sh')",
                "system('/bin/bash')", "pty.spawn",
                "nc -e /bin/", "ncat -e", "socat exec:",
            ]
            try:
                text = content.decode('utf-8', errors='ignore')
                for kw in HIGH_CONF_KEYWORDS:
                    if kw.lower() in text.lower():
                        found.append(f"keyword:{kw}")
                        details.append(f"High-risk keyword found: '{kw}'")
            except Exception:
                pass

        # ── Verdict ──────────────────────────────────────────────────────────
        # Critical patterns → always Malicious
        CRITICAL = {'shellcode','reverse_shell','powershell_encoded','credential_dumping'}
        # High-confidence patterns → Suspicious if 2+ found
        HIGH     = {'suspicious_functions','suspicious_commands','suspicious_antidebug',
                    'suspicious_persistence','suspicious_macros'}
        # Supporting evidence → only contribute if combined with other findings

        critical_hits = [p for p in found if p in CRITICAL]
        high_hits     = [p for p in found if p in HIGH]
        keyword_hits  = [p for p in found if p.startswith('keyword:')]
        all_hits      = found

        if critical_hits:
            r["verdict"] = "Malicious"
        elif len(high_hits) >= 2 or (len(high_hits) >= 1 and len(keyword_hits) >= 1):
            r["verdict"] = "Suspicious"
        elif len(all_hits) >= 4:
            r["verdict"] = "Suspicious"
        elif len(all_hits) >= 1:
            r["verdict"] = "Potentially Suspicious"
        else:
            r["verdict"] = "Clean"

        r["patterns"] = found
        r["details"]  = details if details else ["No threats detected."]

    except Exception as e:
        r["verdict"] = "Error"
        r["details"] = [f"Scan error: {str(e)}"]
    return r

def get_processes():
    procs = []
    for proc in psutil.process_iter(['pid','name','cmdline','memory_percent',
                                      'create_time','num_threads','ppid','cpu_percent']):
        try:
            info = proc.info
            if info['name'].lower() in ['system idle process','registry']: continue
            cmdline = ' '.join(info['cmdline']) if info['cmdline'] else ""
            is_sys = info['name'].lower() in (p.lower() for p in WINDOWS_SYSTEM_PROCESSES)
            suspicious, fix = False, ""
            if not is_sys:
                suspicious = any(kw in cmdline.lower() for kw in SUSPICIOUS_KEYWORDS)
                if suspicious:
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw in cmdline.lower():
                            fix = KEYWORD_FIX.get(kw, "Investigate this process."); break
            procs.append({
                'pid': info['pid'], 'name': info['name'], 'cmdline': cmdline,
                'suspicious': suspicious, 'system_process': is_sys, 'fix_suggestion': fix,
                'cpu_percent':    round(info.get('cpu_percent',0) or 0, 1),
                'memory_percent': round(info.get('memory_percent',0) or 0, 2),
                'create_time':    datetime.fromtimestamp(info.get('create_time',0)).strftime('%H:%M:%S'),
                'num_threads': info.get('num_threads',0), 'ppid': info.get('ppid',0),
            })
        except: continue
    return procs

def get_network_connections():
    conns = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            pname = "N/A"
            if conn.pid:
                try: pname = psutil.Process(conn.pid).name()
                except: pass
            suspicious, reasons = False, []
            if conn.raddr:
                rp, ri = conn.raddr.port, conn.raddr.ip
                if rp in SUSPICIOUS_PORTS and rp not in WHITELIST_PORTS:
                    suspicious = True; reasons.append(f"Suspicious port {rp}")
                if ri not in WHITELIST_IPS:
                    try:
                        for rng in SUSPICIOUS_IP_RANGES:
                            if ipaddress.ip_address(ri) in ipaddress.ip_network(rng):
                                suspicious = True; reasons.append(f"Private IP {ri}"); break
                    except: pass
            conns.append({
                'pid': conn.pid, 'process_name': pname,
                'laddr': laddr, 'raddr': raddr, 'status': conn.status,
                'suspicious': suspicious, 'reasons': reasons,
                'fix_suggestion': "Investigate. Consider blocking via firewall." if suspicious else "",
            })
        except: continue
    return conns

def get_system_health():
    cpu  = psutil.cpu_percent(interval=0.3)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net  = psutil.net_io_counters()
    return {
        'cpu': cpu, 'mem_percent': mem.percent,
        'mem_used': mem.used, 'mem_total': mem.total,
        'disk_percent': disk.percent, 'disk_used': disk.used, 'disk_total': disk.total,
        'net_sent': net.bytes_sent, 'net_recv': net.bytes_recv,
    }

def get_system_uptime():
    sec = time.time() - psutil.boot_time()
    d = int(sec//86400); h = int((sec%86400)//3600); m = int((sec%3600)//60)
    return f"{d}d {h}h {m}m"

def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        if proc.name().lower() in (p.lower() for p in CRITICAL_SYSTEM_PROCESSES):
            return False, "Cannot terminate critical system process"
        proc.terminate()
        try: proc.wait(timeout=3)
        except psutil.TimeoutExpired: proc.kill()
        return True, f"Process {pid} terminated successfully"
    except psutil.NoSuchProcess: return False, "Process not found"
    except psutil.AccessDenied:  return False, "Access denied — run as administrator"
    except Exception as e:       return False, str(e)

def bytes_human(b):
    for u in ['B','KB','MB','GB','TB']:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"



# ═══════════════════════════════════════════════════════════════════════════════
#  ALERT ENGINE  — background monitor + alert store
# ═══════════════════════════════════════════════════════════════════════════════
ALERT_LEVELS = {
    "critical": {"color": DANGER,  "icon": "🔴", "sound": True},
    "warning":  {"color": WARNING, "icon": "🟡", "sound": True},
    "info":     {"color": ACCENT,  "icon": "🔵", "sound": False},
}

class AlertEngine:
    """Background thread that monitors processes and network every 10s."""
    MAX_ALERTS = 200

    def __init__(self, app):
        self.app         = app
        self._alerts     = deque(maxlen=self.MAX_ALERTS)
        self._callbacks  = []
        self._seen_pids  = set()
        self._seen_conns = set()
        self._enabled    = True
        self._sound_on   = True
        self.email       = EmailNotifier()        # email notifier
        self._thread     = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def subscribe(self, callback):
        self._callbacks.append(callback)

    def get_alerts(self):
        return list(self._alerts)

    def clear_alerts(self):
        self._alerts.clear()
        self._notify_all(None)

    def set_enabled(self, val):
        self._enabled = val

    def set_sound(self, val):
        self._sound_on = val

    def unread_count(self):
        return sum(1 for a in self._alerts if not a.get("read"))

    def mark_all_read(self):
        for a in self._alerts:
            a["read"] = True

    def _loop(self):
        time.sleep(4)
        while True:
            if self._enabled:
                try:
                    self._scan_processes()
                    self._scan_network()
                    self._check_resources()
                except Exception:
                    pass
            time.sleep(10)

    def _scan_processes(self):
        for proc in psutil.process_iter(["pid","name","cmdline"]):
            try:
                info    = proc.info
                pid     = info["pid"]
                name    = info["name"]
                cmdline = " ".join(info["cmdline"]) if info["cmdline"] else ""
                if name.lower() in (p.lower() for p in WINDOWS_SYSTEM_PROCESSES):
                    continue
                if pid not in self._seen_pids:
                    hit = next((kw for kw in SUSPICIOUS_KEYWORDS if kw in cmdline.lower()), None)
                    if hit:
                        self._seen_pids.add(pid)
                        self._fire({
                            "level":    "critical",
                            "category": "Process",
                            "title":    "Suspicious Process Detected",
                            "message":  f"'{name}' (PID {pid})  ·  keyword: '{hit}'",
                            "detail":   cmdline[:200] or "N/A",
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def _scan_network(self):
        for conn in psutil.net_connections(kind="inet"):
            try:
                if not conn.raddr:
                    continue
                rp  = conn.raddr.port
                ri  = conn.raddr.ip
                key = f"{ri}:{rp}:{conn.pid}"
                if key in self._seen_conns:
                    continue
                reason = ""
                if rp in SUSPICIOUS_PORTS and rp not in WHITELIST_PORTS:
                    reason = f"Connection on suspicious port {rp}"
                if not reason and ri not in WHITELIST_IPS:
                    try:
                        for rng in SUSPICIOUS_IP_RANGES:
                            if ipaddress.ip_address(ri) in ipaddress.ip_network(rng):
                                reason = f"Connection to private IP {ri}"
                                break
                    except Exception:
                        pass
                if reason:
                    self._seen_conns.add(key)
                    pname = "Unknown"
                    try:
                        if conn.pid: pname = psutil.Process(conn.pid).name()
                    except Exception:
                        pass
                    self._fire({
                        "level":    "warning",
                        "category": "Network",
                        "title":    "Suspicious Connection Detected",
                        "message":  f"'{pname}'  →  {ri}:{rp}",
                        "detail":   reason,
                    })
            except Exception:
                continue

    def _check_resources(self):
        try:
            cpu = psutil.cpu_percent(interval=0.5)
            mem = psutil.virtual_memory().percent
            if cpu > 95:
                self._fire({
                    "level": "warning", "category": "System",
                    "title": "CPU Usage Critical",
                    "message": f"CPU at {cpu:.1f}% — possible runaway process",
                    "detail": "Open Process Monitor to investigate.",
                })
            if mem > 92:
                self._fire({
                    "level": "warning", "category": "System",
                    "title": "Memory Usage Critical",
                    "message": f"RAM at {mem:.1f}%",
                    "detail": "Consider closing unused applications.",
                })
        except Exception:
            pass

    def _fire(self, data):
        alert = {
            **data,
            "time":      datetime.now().strftime("%H:%M:%S"),
            "date":      datetime.now().strftime("%Y-%m-%d"),
            "timestamp": datetime.now(),
            "read":      False,
        }
        self._alerts.appendleft(alert)
        try:
            if self._sound_on and ALERT_LEVELS[data["level"]]["sound"]:
                import winsound
                self.app.after(0, lambda: winsound.MessageBeep(winsound.MB_ICONEXCLAMATION))
        except Exception:
            pass
        # Send email notification (runs in background thread)
        self.email.send(alert)
        self.app.after(0, lambda a=alert: self._notify_all(a))

    def _notify_all(self, alert):
        for cb in self._callbacks:
            try: cb(alert)
            except Exception: pass


# ═══════════════════════════════════════════════════════════════════════════════
#  EMAIL NOTIFIER
# ═══════════════════════════════════════════════════════════════════════════════
class EmailNotifier:
    """
    Automatic email notifier — detects SMTP settings from email domain.
    Supports Gmail, Outlook, Yahoo, iCloud and any custom SMTP.
    """

    # Auto-detected SMTP settings by email domain
    SMTP_PROVIDERS = {
        "gmail.com":      ("smtp.gmail.com",     587, "starttls"),
        "googlemail.com": ("smtp.gmail.com",     587, "starttls"),
        "outlook.com":    ("smtp.office365.com", 587, "starttls"),
        "hotmail.com":    ("smtp.office365.com", 587, "starttls"),
        "live.com":       ("smtp.office365.com", 587, "starttls"),
        "yahoo.com":      ("smtp.mail.yahoo.com",587, "starttls"),
        "ymail.com":      ("smtp.mail.yahoo.com",587, "starttls"),
        "icloud.com":     ("smtp.mail.me.com",   587, "starttls"),
        "me.com":         ("smtp.mail.me.com",   587, "starttls"),
        "zoho.com":       ("smtp.zoho.com",       587, "starttls"),
        "protonmail.com": ("smtp.protonmail.ch",  587, "starttls"),
        "proton.me":      ("smtp.protonmail.ch",  587, "starttls"),
    }

    DEFAULT_CFG = {
        "enabled":          False,
        "sender_email":     "",
        "sender_password":  "",
        "receiver_email":   "",
        "send_on":          ["critical", "warning"],
    }

    def __init__(self):
        self.cfg          = self._load()
        self._last_status = ""    # last send result

    # ── SMTP auto-detection ───────────────────────────────────────────────────
    @classmethod
    def detect_smtp(cls, email: str):
        """Return (host, port, mode) for the given email address automatically."""
        try:
            domain = email.strip().lower().split("@")[1]
            if domain in cls.SMTP_PROVIDERS:
                return cls.SMTP_PROVIDERS[domain]
            # Try common smtp. prefix as fallback
            return (f"smtp.{domain}", 587, "starttls")
        except Exception:
            return ("smtp.gmail.com", 587, "starttls")

    # ── Config persistence ────────────────────────────────────────────────────
    def _load(self):
        try:
            if os.path.exists(EMAIL_CFG_FILE):
                with open(EMAIL_CFG_FILE, "r") as f:
                    saved = json.load(f)
                    cfg   = dict(self.DEFAULT_CFG)
                    cfg.update(saved)
                    return cfg
        except Exception:
            pass
        return dict(self.DEFAULT_CFG)

    def save(self):
        try:
            with open(EMAIL_CFG_FILE, "w") as f:
                json.dump(self.cfg, f, indent=2)
        except Exception as e:
            print(f"Email config save error: {e}")

    # ── Send ─────────────────────────────────────────────────────────────────
    def send(self, alert: dict):
        """Non-blocking — fires in a daemon thread."""
        if not self.cfg.get("enabled"):
            return
        if alert.get("level") not in self.cfg.get("send_on", []):
            return
        threading.Thread(target=self._send_thread, args=(alert,), daemon=True).start()

    def _send_thread(self, alert: dict):
        sender   = self.cfg.get("sender_email",   "").strip()
        password = self.cfg.get("sender_password","").strip()
        receiver = self.cfg.get("receiver_email", "").strip()
        if not sender or not password or not receiver:
            return
        host, port, mode = self.detect_smtp(sender)
        try:
            self._do_send(sender, password, receiver, host, port, mode, alert)
            self._last_status = "ok"
        except smtplib.SMTPAuthenticationError:
            self._last_status = "auth_error"
            print("Email: Authentication failed — check App Password.")
        except Exception as e:
            self._last_status = f"error: {e}"
            print(f"Email error: {e}")

    def _do_send(self, sender, password, receiver, host, port, mode, alert):
        level     = alert.get("level","").upper()
        icon      = {"CRITICAL":"🔴","WARNING":"🟡","INFO":"🔵"}.get(level,"⚠")
        hdr_color = {"CRITICAL":"#c62828","WARNING":"#d29922"}.get(level,"#1565c0")

        html = (
            "<html><body style='font-family:Arial,sans-serif;background:#0d1117;"
            "color:#e6edf3;padding:24px;'>"
            "<div style='max-width:600px;margin:auto;background:#161b22;"
            "border-radius:8px;overflow:hidden;'>"
            f"<div style='background:{hdr_color};padding:16px 24px;'>"
            f"<h2 style='margin:0;color:#fff;'>{icon} ProXDefend Security Alert</h2>"
            "</div><div style='padding:24px;'>"
            "<table style='width:100%;border-collapse:collapse;'>"
            f"<tr><td style='color:#8b949e;width:140px;padding:8px 0;'>Alert Level</td>"
            f"<td style='color:#e6edf3;font-weight:bold;'>{level}</td></tr>"
            f"<tr><td style='color:#8b949e;padding:8px 0;'>Category</td>"
            f"<td style='color:#e6edf3;'>{alert.get('category','')}</td></tr>"
            f"<tr><td style='color:#8b949e;padding:8px 0;'>Title</td>"
            f"<td style='color:#e6edf3;font-weight:bold;'>{alert.get('title','')}</td></tr>"
            f"<tr><td style='color:#8b949e;padding:8px 0;'>Message</td>"
            f"<td style='color:#e6edf3;'>{alert.get('message','')}</td></tr>"
            f"<tr><td style='color:#8b949e;padding:8px 0;'>Detail</td>"
            f"<td style='color:#e6edf3;'>{alert.get('detail','')}</td></tr>"
            f"<tr><td style='color:#8b949e;padding:8px 0;'>Date &amp; Time</td>"
            f"<td style='color:#e6edf3;'>{alert.get('date','')} at {alert.get('time','')}</td></tr>"
            "</table><hr style='border:1px solid #30363d;margin:20px 0;'>"
            "<p style='color:#8b949e;font-size:12px;margin:0;'>"
            "Sent automatically by ProXDefend Security Monitor.<br>"
            "Open ProXDefend to investigate and take action.</p>"
            "</div></div></body></html>"
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[ProXDefend] {icon} {level} — {alert.get('title','')}"
        msg["From"]    = f"ProXDefend <{sender}>"
        msg["To"]      = receiver
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(host, port, timeout=15) as srv:
            srv.ehlo()
            if mode == "starttls":
                srv.starttls()
            srv.login(sender, password)
            srv.sendmail(sender, receiver, msg.as_string())

    def test_send(self):
        """Send a test alert email (force-send ignoring enabled flag)."""
        old = self.cfg.get("enabled")
        self.cfg["enabled"] = True
        old_on = self.cfg.get("send_on")
        self.cfg["send_on"] = ["warning"]
        self.send({
            "level": "warning", "category": "Test",
            "title":   "ProXDefend Email Test",
            "message": "Email notifications are working correctly!",
            "detail":  "This is a test alert sent from ProXDefend.",
            "date":    datetime.now().strftime("%Y-%m-%d"),
            "time":    datetime.now().strftime("%H:%M:%S"),
        })
        self.cfg["enabled"] = old
        self.cfg["send_on"] = old_on


# ═══════════════════════════════════════════════════════════════════════════════
#  TOAST NOTIFICATION  — slides in from top-right corner
# ═══════════════════════════════════════════════════════════════════════════════
class ToastNotification:
    """Animated toast that appears top-right and auto-dismisses after 5 s."""
    _active = []

    def __init__(self, app, alert):
        self.app   = app
        self.alert = alert
        self._win  = None
        self._show()

    def _show(self):
        level  = self.alert.get("level", "info")
        config = ALERT_LEVELS.get(level, ALERT_LEVELS["info"])
        color  = config["color"]
        icon   = config["icon"]

        offset = len([t for t in ToastNotification._active
                      if t._win and t._win.winfo_exists()])
        ToastNotification._active.append(self)

        win = tk.Toplevel(self.app)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=CARD)
        self._win = win

        WIN_W, WIN_H = 370, 95
        screen_w = self.app.winfo_screenwidth()
        target_x = screen_w - WIN_W - 18
        y        = 18 + offset * (WIN_H + 10)
        win.geometry(f"{WIN_W}x{WIN_H}+{screen_w}+{y}")  # start off-screen

        # Top colour bar
        tk.Frame(win, bg=color, height=3).pack(fill="x")

        body = tk.Frame(win, bg=CARD, padx=14, pady=8)
        body.pack(fill="both", expand=True)

        # Title row
        top_row = tk.Frame(body, bg=CARD)
        top_row.pack(fill="x")
        tk.Label(top_row, text=icon+" ", font=(F, 13), bg=CARD, fg=color).pack(side="left")
        tk.Label(top_row, text=self.alert.get("title",""),
                 font=(F, 10, "bold"), bg=CARD, fg=TEXT).pack(side="left")
        close_lbl = tk.Label(top_row, text="✕", font=(F, 9),
                              bg=CARD, fg=MUTED, cursor="hand2")
        close_lbl.pack(side="right")
        close_lbl.bind("<Button-1>", lambda e: self._dismiss())

        # Message
        tk.Label(body, text=self.alert.get("message",""),
                 font=(F, 9), bg=CARD, fg=MUTED,
                 anchor="w", wraplength=330).pack(fill="x", pady=(3,0))

        # Footer
        tk.Label(body,
                 text=f"{self.alert.get('category','')}  ·  {self.alert.get('time','')}",
                 font=(F, 8), bg=CARD, fg=MUTED).pack(anchor="w", pady=(4,0))

        # Slide-in animation
        self._slide_in(win, target_x, WIN_W, WIN_H, y)
        win.after(5000, self._dismiss)

    def _slide_in(self, win, target_x, w, h, y):
        screen_w = self.app.winfo_screenwidth()
        start_x  = screen_w + 10

        def step(cx):
            if not win.winfo_exists(): return
            nx = cx + int((target_x - cx) * 0.45)
            win.geometry(f"{w}x{h}+{nx}+{y}")
            if abs(nx - target_x) > 2:
                win.after(14, lambda: step(nx))
            else:
                win.geometry(f"{w}x{h}+{target_x}+{y}")

        step(start_x)

    def _dismiss(self):
        try:
            if self._win and self._win.winfo_exists():
                self._win.destroy()
        except Exception:
            pass
        try:
            ToastNotification._active.remove(self)
        except ValueError:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
#  TTK STYLE SETUP
# ═══════════════════════════════════════════════════════════════════════════════
def setup_styles():
    s = ttk.Style()
    s.theme_use("clam")

    # Treeview
    s.configure("App.Treeview",
                 background=CARD, foreground=TEXT, fieldbackground=CARD,
                 rowheight=28, borderwidth=0, font=(F, 9))
    s.configure("App.Treeview.Heading",
                 background=CARD2, foreground=ACCENT,
                 relief="flat", font=(F, 9, "bold"), borderwidth=0)
    s.map("App.Treeview",
          background=[("selected", ACCENT_DIM)],
          foreground=[("selected", TEXT)])

    # Scrollbars
    s.configure("App.Vertical.TScrollbar",
                 background=CARD2, troughcolor=BG, arrowcolor=MUTED, borderwidth=0)
    s.configure("App.Horizontal.TScrollbar",
                 background=CARD2, troughcolor=BG, arrowcolor=MUTED, borderwidth=0)

    # Progress bar
    s.configure("App.Horizontal.TProgressbar",
                 troughcolor=BORDER, background=ACCENT,
                 borderwidth=0, lightcolor=ACCENT, darkcolor=ACCENT)


# ═══════════════════════════════════════════════════════════════════════════════
#  REUSABLE COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════
def make_navbar_button(parent, text, command, active=False):
    """Outline button matching the original browser navbar style."""
    color = TEXT if active else MUTED
    bg    = CARD2 if active else CARD
    btn = tk.Label(parent, text=text, font=(F, 10),
                   bg=bg, fg=color,
                   padx=16, pady=6, cursor="hand2",
                   relief="flat",
                   highlightbackground=BORDER,
                   highlightthickness=1)
    def on_enter(e): btn.configure(bg=CARD2, fg=TEXT)
    def on_leave(e): btn.configure(bg=bg,    fg=color)
    btn.bind("<Enter>",    on_enter)
    btn.bind("<Leave>",    on_leave)
    btn.bind("<Button-1>", lambda e: command())
    return btn


def make_action_button(parent, text, command,
                       bg=ACCENT, fg=BG, width=None):
    """Solid filled action button."""
    kw = {"width": width} if width else {}
    btn = tk.Label(parent, text=text, font=(F, 10, "bold"),
                   bg=bg, fg=fg, padx=14, pady=7,
                   cursor="hand2", relief="flat", **kw)
    def on_enter(e): btn.configure(bg=_lighten(bg, 20))
    def on_leave(e): btn.configure(bg=bg)
    btn.bind("<Enter>",    on_enter)
    btn.bind("<Leave>",    on_leave)
    btn.bind("<Button-1>", lambda e: command())
    return btn


def _lighten(hex_color, amount=20):
    try:
        r = min(255, int(hex_color[1:3],16)+amount)
        g = min(255, int(hex_color[3:5],16)+amount)
        b = min(255, int(hex_color[5:7],16)+amount)
        return f"#{r:02x}{g:02x}{b:02x}"
    except:
        return hex_color


def make_tree(parent, columns, col_widths, heights=18):
    """Build a styled Treeview inside parent."""
    frame = tk.Frame(parent, bg=CARD)
    frame.pack(fill="both", expand=True)
    sb_y = ttk.Scrollbar(frame, orient="vertical",   style="App.Vertical.TScrollbar")
    sb_x = ttk.Scrollbar(frame, orient="horizontal", style="App.Horizontal.TScrollbar")
    tv = ttk.Treeview(frame, columns=columns, show="headings",
                      style="App.Treeview",
                      yscrollcommand=sb_y.set, xscrollcommand=sb_x.set,
                      height=heights)
    sb_y.configure(command=tv.yview)
    sb_x.configure(command=tv.xview)
    sb_y.pack(side="right",  fill="y")
    sb_x.pack(side="bottom", fill="x")
    tv.pack(fill="both", expand=True)
    for i, (col, w) in enumerate(zip(columns, col_widths)):
        tv.heading(i, text=col)
        tv.column(i, width=w, anchor="w" if i <= 1 else "center")
    tv.tag_configure("suspicious", foreground=DANGER,  background="#1e0e0d")
    tv.tag_configure("system",     foreground=ACCENT)
    tv.tag_configure("even",       background=CARD)
    tv.tag_configure("odd",        background=CARD2)
    tv.tag_configure("clean",      foreground=SUCCESS)
    return tv


def scrollable_frame(parent):
    """Return (outer_frame, inner_frame) — inner scrolls vertically."""
    canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
    vsb    = ttk.Scrollbar(parent, orient="vertical",
                            command=canvas.yview,
                            style="App.Vertical.TScrollbar")
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(fill="both", expand=True)
    inner = tk.Frame(canvas, bg=BG)
    win   = canvas.create_window((0,0), window=inner, anchor="nw")
    inner.bind("<Configure>",
               lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>",
                lambda e: canvas.itemconfig(win, width=e.width))
    # Mouse-wheel scrolling
    def _wheel(e):
        canvas.yview_scroll(int(-1*(e.delta/120)), "units")
    canvas.bind_all("<MouseWheel>", _wheel)
    return canvas, inner


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION WINDOW
# ═══════════════════════════════════════════════════════════════════════════════
class ProXDefendApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ProXDefend – System Monitoring & Security")
        self.geometry("1280x780")
        self.minsize(900, 600)
        self.configure(bg=BG)
        self._after_ids   = []
        self._active_page = "home"
        setup_styles()
        self._alert_engine = AlertEngine(self)
        self._build()
        self._alert_engine.subscribe(self._on_alert)
        self._show_page("home")
        self._start_clock()
        self.protocol("WM_DELETE_WINDOW", self._quit)
        self._start_tray()
        self.after(2000, self._show_tray_hint)

    # ── Top Navbar ────────────────────────────────────────────────────────────
    def _build(self):
        self._build_navbar()
        # Page container — all pages stacked here
        self._container = tk.Frame(self, bg=BG)
        self._container.pack(fill="both", expand=True)
        self._pages = {}
        for name, Cls in [("home",      HomePage),
                           ("processes", ProcessesPage),
                           ("network",   NetworkPage),
                           ("scanner",   ScannerPage),
                           ("alerts",    AlertsPage)]:
            page = Cls(self._container, self)
            self._pages[name] = page
            page.place(relx=0, rely=0, relwidth=1, relheight=1)

    def _build_navbar(self):
        nav = tk.Frame(self, bg=CARD, pady=0)
        nav.pack(fill="x")
        # Bottom border line
        border = tk.Frame(self, bg=BORDER, height=1)
        border.pack(fill="x")

        inner = tk.Frame(nav, bg=CARD)
        inner.pack(fill="x", padx=24)

        # Brand name
        tk.Label(inner, text="ProXDefend", font=(F, 16, "bold"),
                 bg=CARD, fg=TEXT).pack(side="left", pady=12)

        # Nav buttons (right side)
        right = tk.Frame(inner, bg=CARD)
        right.pack(side="right", pady=10)

        self._nav_btns = {}
        for name, label in [("processes","Processes"),
                             ("network",  "Network"),
                             ("scanner",  "Scanner")]:
            btn = make_navbar_button(right, label,
                                     command=lambda n=name: self._show_page(n))
            btn.pack(side="left", padx=4)
            self._nav_btns[name] = btn

        # Alerts bell button with badge
        self._alert_btn_frame = tk.Frame(right, bg=CARD)
        self._alert_btn_frame.pack(side="left", padx=(8,4))
        self._alert_bell = tk.Label(self._alert_btn_frame,
                                     text="🔔  Alerts",
                                     font=(F, 10), bg=CARD, fg=MUTED,
                                     padx=16, pady=6, cursor="hand2",
                                     relief="flat",
                                     highlightbackground=BORDER,
                                     highlightthickness=1)
        self._alert_bell.pack()
        self._alert_bell.bind("<Button-1>", lambda e: self._show_page("alerts"))
        self._alert_bell.bind("<Enter>",    lambda e: self._alert_bell.configure(bg=CARD2, fg=TEXT))
        self._alert_bell.bind("<Leave>",    lambda e: self._alert_bell.configure(
            bg=CARD2 if self._active_page=="alerts" else CARD,
            fg=TEXT  if self._active_page=="alerts" else MUTED))
        self._nav_btns["alerts"] = self._alert_bell

        # Badge for unread count
        self._badge_var = tk.StringVar(value="")
        self._badge_lbl = tk.Label(self._alert_btn_frame,
                                    textvariable=self._badge_var,
                                    font=(F, 7, "bold"),
                                    bg=DANGER, fg="white",
                                    padx=4, pady=1, relief="flat")
        # Will be placed on top-right of bell button when count > 0

        # Uptime label
        self._uptime_var = tk.StringVar(value="")
        tk.Label(inner, textvariable=self._uptime_var,
                 font=(F, 9), bg=CARD, fg=MUTED).pack(side="right", padx=16)

    def _show_page(self, name):
        self._active_page = name
        # Update nav button states
        for n, btn in self._nav_btns.items():
            if n == name:
                btn.configure(bg=CARD2, fg=TEXT, highlightbackground=TEXT)
            else:
                btn.configure(bg=CARD, fg=MUTED, highlightbackground=BORDER)
        self._pages[name].tkraise()
        self._pages[name].on_show()

    def _start_clock(self):
        def tick():
            self._uptime_var.set(f"Uptime: {get_system_uptime()}")
            try: self._pages[self._active_page].auto_tick()
            except: pass
            aid = self.after(5000, tick)
            self._after_ids.append(aid)
        tick()

    def _show_tray_hint(self):
        """Show a small info label on first launch explaining tray behaviour."""
        bar = tk.Frame(self, bg="#1f4068", pady=5)
        bar.pack(fill="x", side="bottom")
        tk.Label(bar,
                 text="🛡  ProXDefend runs in the system tray when you close this window.  "
                      "Double-click the tray icon to reopen.  "
                      "Right-click the tray icon → 'Exit ProXDefend' to fully quit.",
                 font=(F, 9), bg="#1f4068", fg="#cde4f5").pack(side="left", padx=16)
        close_btn = tk.Label(bar, text="✕", font=(F, 10), bg="#1f4068",
                              fg=MUTED, cursor="hand2", padx=8)
        close_btn.pack(side="right", padx=8)
        close_btn.bind("<Button-1>", lambda e: bar.destroy())
        # Auto-hide after 8 seconds
        bar.after(8000, bar.destroy)

    # ── System Tray (pure ctypes — no external libraries needed) ───────────────
    def _start_tray(self):
        """Launch the Windows system tray icon in a background thread."""
        self._tray_running = True
        self._tray_hwnd    = None
        t = threading.Thread(target=self._tray_thread, daemon=True)
        t.start()

    def _tray_thread(self):
        """Background thread: creates a hidden window to handle tray messages."""
        try:
            shell32  = ctypes.windll.shell32
            user32   = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            hinstance  = kernel32.GetModuleHandleW(None)
            class_name = "ProXDefendTray"

            # 64-bit safe types — WPARAM/LPARAM are 64-bit on 64-bit Windows.
            # Using wintypes.WPARAM/LPARAM causes OverflowError on some messages.
            WPARAM_T  = ctypes.c_uint64
            LPARAM_T  = ctypes.c_int64
            LRESULT_T = ctypes.c_int64

            # Set correct argtypes/restype for DefWindowProcW
            user32.DefWindowProcW.restype  = LRESULT_T
            user32.DefWindowProcW.argtypes = [
                ctypes.wintypes.HWND, ctypes.c_uint, WPARAM_T, LPARAM_T]

            WNDPROCTYPE = ctypes.WINFUNCTYPE(
                LRESULT_T,
                ctypes.wintypes.HWND,
                ctypes.c_uint,
                WPARAM_T,
                LPARAM_T,
            )

            def wnd_proc(hwnd, msg, wparam, lparam):
                try:
                    # Mask lower 16 bits to get the tray notification code
                    notif = lparam & 0xFFFF
                    if msg == WM_TRAYICON:
                        if notif == WM_LBUTTONDBLCLK:
                            self.after(0, self._show_window)
                        elif notif == WM_RBUTTONUP:
                            self.after(0, lambda: self._show_tray_menu(hwnd))
                    elif msg == WM_DESTROY:
                        user32.PostQuitMessage(0)
                        return LRESULT_T(0)
                except Exception:
                    pass
                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

            wnd_proc_ptr = WNDPROCTYPE(wnd_proc)

            # Register window class
            class WNDCLASS(ctypes.Structure):
                _fields_ = [
                    ("style",         ctypes.c_uint),
                    ("lpfnWndProc",   WNDPROCTYPE),
                    ("cbClsExtra",    ctypes.c_int),
                    ("cbWndExtra",    ctypes.c_int),
                    ("hInstance",     ctypes.wintypes.HANDLE),
                    ("hIcon",         ctypes.wintypes.HANDLE),
                    ("hCursor",       ctypes.wintypes.HANDLE),
                    ("hbrBackground", ctypes.wintypes.HANDLE),
                    ("lpszMenuName",  ctypes.c_wchar_p),
                    ("lpszClassName", ctypes.c_wchar_p),
                ]

            wc = WNDCLASS()
            wc.style         = CS_HREDRAW | CS_VREDRAW
            wc.lpfnWndProc   = wnd_proc_ptr
            wc.hInstance     = hinstance
            wc.hIcon         = user32.LoadIconW(None, IDI_APPLICATION)
            wc.hCursor       = user32.LoadCursorW(None, IDC_ARROW)
            wc.lpszClassName = class_name
            user32.RegisterClassW(ctypes.byref(wc))

            # Create hidden message window
            hwnd = user32.CreateWindowExW(
                0, class_name, "ProXDefend",
                WS_OVERLAPPED, 0, 0, 0, 0, None, None, hinstance, None)
            self._tray_hwnd = hwnd

            # Load a stock shield/app icon
            hicon = user32.LoadIconW(None, IDI_APPLICATION)

            # NOTIFYICONDATA structure
            class NOTIFYICONDATA(ctypes.Structure):
                _fields_ = [
                    ("cbSize",           ctypes.wintypes.DWORD),
                    ("hWnd",             ctypes.wintypes.HWND),
                    ("uID",              ctypes.wintypes.UINT),
                    ("uFlags",           ctypes.wintypes.UINT),
                    ("uCallbackMessage", ctypes.wintypes.UINT),
                    ("hIcon",            ctypes.wintypes.HANDLE),
                    ("szTip",            ctypes.c_wchar * 128),
                    ("dwState",          ctypes.wintypes.DWORD),
                    ("dwStateMask",      ctypes.wintypes.DWORD),
                    ("szInfo",           ctypes.c_wchar * 256),
                    ("uVersion",         ctypes.wintypes.UINT),
                    ("szInfoTitle",      ctypes.c_wchar * 64),
                    ("dwInfoFlags",      ctypes.wintypes.DWORD),
                ]

            nid = NOTIFYICONDATA()
            nid.cbSize           = ctypes.sizeof(NOTIFYICONDATA)
            nid.hWnd             = hwnd
            nid.uID              = 1
            nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP
            nid.uCallbackMessage = WM_TRAYICON
            nid.hIcon            = hicon
            nid.szTip            = "ProXDefend — Security Monitor"
            shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
            self._tray_nid = nid

            # Show balloon tip on first hide
            self._tray_show_balloon(
                nid, shell32,
                "ProXDefend is running in the background",
                "Monitoring continues. Double-click the tray icon to reopen. Right-click for more options.")

            # Message loop
            class MSG(ctypes.Structure):
                _fields_ = [
                    ("hwnd",    ctypes.wintypes.HWND),
                    ("message", ctypes.c_uint),
                    ("wParam",  ctypes.wintypes.WPARAM),
                    ("lParam",  ctypes.wintypes.LPARAM),
                    ("time",    ctypes.wintypes.DWORD),
                    ("pt",      ctypes.wintypes.POINT),
                ]

            msg = MSG()
            while self._tray_running:
                bRet = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if bRet == 0 or bRet == -1:
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

            # Remove tray icon on exit
            try:
                shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
            except Exception:
                pass

        except Exception as e:
            print(f"Tray thread error: {e}")

    def _tray_show_balloon(self, nid, shell32, title, message):
        """Show a Windows balloon notification from the tray icon."""
        try:
            nid.uFlags    = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO
            nid.szInfoTitle = title[:63]
            nid.szInfo      = message[:255]
            nid.dwInfoFlags = NIIF_INFO
            shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        except Exception:
            pass

    def _show_tray_menu(self, hwnd):
        """Show right-click context menu near the tray icon."""
        try:
            user32 = ctypes.windll.user32
            hmenu  = user32.CreatePopupMenu()

            # Menu items — IDs 1001–1006
            user32.AppendMenuW(hmenu, MF_STRING,    1001, "Open ProXDefend")
            user32.AppendMenuW(hmenu, MF_STRING,    1002, "Alerts Center")
            user32.AppendMenuW(hmenu, MF_SEPARATOR, 0,    None)
            mon_label = "Monitoring: ON  ✓" if self._alert_engine._enabled else "Monitoring: OFF"
            snd_label = "Sound Alerts: ON  ✓" if self._alert_engine._sound_on else "Sound Alerts: OFF"
            user32.AppendMenuW(hmenu, MF_STRING, 1003, mon_label)
            user32.AppendMenuW(hmenu, MF_STRING, 1004, snd_label)
            user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
            user32.AppendMenuW(hmenu, MF_STRING, 1005, "Exit ProXDefend")

            # Get cursor position and show menu
            pt = ctypes.wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.SetForegroundWindow(hwnd)
            cmd = user32.TrackPopupMenu(
                hmenu, TPM_LEFTALIGN | TPM_RETURNCMD,
                pt.x, pt.y, 0, hwnd, None)
            user32.DestroyMenu(hmenu)

            if cmd == 1001:   self._show_window()
            elif cmd == 1002: self._show_window(); self._show_page("alerts")
            elif cmd == 1003: self._alert_engine.set_enabled(not self._alert_engine._enabled)
            elif cmd == 1004: self._alert_engine.set_sound(not self._alert_engine._sound_on)
            elif cmd == 1005: self._do_quit()
        except Exception as e:
            print(f"Tray menu error: {e}")

    def _show_window(self):
        """Restore main window from tray."""
        self.deiconify()
        self.lift()
        self.focus_force()

    def _hide_to_tray(self):
        """Hide the window — tray icon stays active."""
        self.withdraw()

    def _on_alert(self, alert):
        """Called on main thread each time a new alert fires."""
        if alert is not None:
            ToastNotification(self, alert)
        count = self._alert_engine.unread_count()
        if count > 0:
            self._badge_var.set(str(count))
            self._badge_lbl.place(relx=0.72, rely=0.0, anchor="nw")
        else:
            self._badge_lbl.place_forget()

    def _quit(self):
        """Close button → hide to tray, keep monitoring running."""
        self._hide_to_tray()

    def _do_quit(self):
        """Fully terminate the application."""
        self._tray_running = False
        try:
            if self._tray_hwnd:
                ctypes.windll.user32.PostMessageW(self._tray_hwnd, WM_DESTROY, 0, 0)
        except Exception:
            pass
        for aid in self._after_ids:
            try: self.after_cancel(aid)
            except: pass
        self.destroy()


# ═══════════════════════════════════════════════════════════════════════════════
#  HOME / DASHBOARD PAGE
# ═══════════════════════════════════════════════════════════════════════════════
class HomePage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app
        self._cpu_hist = []
        self._mem_hist = []
        self._build()

    def _build(self):
        _, body = scrollable_frame(self)

        # ── Hero section ──────────────────────────────────────────────────────
        hero = tk.Frame(body, bg=BG, pady=60)
        hero.pack(fill="x")

        tk.Label(hero, text="Welcome to ProXDefend",
                 font=(F, 32, "bold"), bg=BG, fg=TEXT).pack()
        tk.Label(hero, text="Advanced system monitoring and security solution",
                 font=(F, 13), bg=BG, fg=MUTED).pack(pady=(8, 36))

        # Feature cards row
        cards_row = tk.Frame(hero, bg=BG)
        cards_row.pack()
        cards_row.columnconfigure(0, weight=1, minsize=280)
        cards_row.columnconfigure(1, weight=1, minsize=280)
        cards_row.columnconfigure(2, weight=1, minsize=280)

        features = [
            ("processes", "⬡⬡⬡",  "Process Management",
             "Monitor and manage running processes\nwith detailed information"),
            ("network",   "≋",     "Network Monitoring",
             "Track network connections and\nidentify potential threats"),
            ("scanner",   "⬟",     "File Scanner",
             "Upload and scan files for\npotential threats"),
        ]
        for col, (page, icon, title, desc) in enumerate(features):
            self._make_feature_card(cards_row, icon, title, desc, page, col)

        # ── System Health section ─────────────────────────────────────────────
        sep = tk.Frame(body, bg=BORDER, height=1)
        sep.pack(fill="x", padx=24, pady=(10, 0))

        health_outer = tk.Frame(body, bg=BG, padx=24, pady=24)
        health_outer.pack(fill="x")

        tk.Label(health_outer, text="System Health",
                 font=(F, 14, "bold"), bg=BG, fg=TEXT).pack(anchor="w", pady=(0, 16))

        health_card = tk.Frame(health_outer, bg=CARD,
                                highlightbackground=BORDER, highlightthickness=1)
        health_card.pack(fill="x")
        inner = tk.Frame(health_card, bg=CARD, padx=24, pady=20)
        inner.pack(fill="x")
        inner.columnconfigure(0, weight=1)
        inner.columnconfigure(1, weight=1)

        # CPU
        cpu_f = tk.Frame(inner, bg=CARD); cpu_f.grid(row=0, column=0, sticky="ew", padx=(0,24), pady=6)
        tk.Label(cpu_f, text="CPU Usage", font=(F, 10), bg=CARD, fg=TEXT).pack(anchor="w")
        self._cpu_bar = ttk.Progressbar(cpu_f, length=400, mode="determinate",
                                         style="App.Horizontal.TProgressbar")
        self._cpu_bar.pack(fill="x", pady=4)
        self._cpu_lbl = tk.Label(cpu_f, text="Loading...", font=(F, 9),
                                  bg=CARD, fg=MUTED)
        self._cpu_lbl.pack(anchor="w")

        # Memory
        mem_f = tk.Frame(inner, bg=CARD); mem_f.grid(row=0, column=1, sticky="ew", padx=(24,0), pady=6)
        tk.Label(mem_f, text="Memory Usage", font=(F, 10), bg=CARD, fg=TEXT).pack(anchor="w")
        self._mem_bar = ttk.Progressbar(mem_f, length=400, mode="determinate",
                                         style="App.Horizontal.TProgressbar")
        self._mem_bar.pack(fill="x", pady=4)
        self._mem_lbl = tk.Label(mem_f, text="Loading...", font=(F, 9),
                                  bg=CARD, fg=MUTED)
        self._mem_lbl.pack(anchor="w")

        # Disk
        disk_f = tk.Frame(inner, bg=CARD); disk_f.grid(row=1, column=0, sticky="ew", padx=(0,24), pady=6)
        tk.Label(disk_f, text="Disk Usage", font=(F, 10), bg=CARD, fg=TEXT).pack(anchor="w")
        self._disk_bar = ttk.Progressbar(disk_f, length=400, mode="determinate",
                                          style="App.Horizontal.TProgressbar")
        self._disk_bar.pack(fill="x", pady=4)
        self._disk_lbl = tk.Label(disk_f, text="Loading...", font=(F, 9),
                                   bg=CARD, fg=MUTED)
        self._disk_lbl.pack(anchor="w")

        # Network I/O
        net_f = tk.Frame(inner, bg=CARD); net_f.grid(row=1, column=1, sticky="ew", padx=(24,0), pady=6)
        tk.Label(net_f, text="Network I/O", font=(F, 10), bg=CARD, fg=TEXT).pack(anchor="w")
        self._net_lbl = tk.Label(net_f, text="Loading...", font=(F, 12, "bold"),
                                  bg=CARD, fg=ACCENT)
        self._net_lbl.pack(anchor="w", pady=(6,0))

        # ── Threat Summary cards ──────────────────────────────────────────────
        sep2 = tk.Frame(body, bg=BORDER, height=1)
        sep2.pack(fill="x", padx=24, pady=(4, 0))

        summary_outer = tk.Frame(body, bg=BG, padx=24, pady=24)
        summary_outer.pack(fill="x")
        tk.Label(summary_outer, text="Threat Summary",
                 font=(F, 14, "bold"), bg=BG, fg=TEXT).pack(anchor="w", pady=(0,16))

        sumrow = tk.Frame(summary_outer, bg=BG)
        sumrow.pack(fill="x")
        for col in range(4): sumrow.columnconfigure(col, weight=1)

        self._sum_vars = {}
        for col, (key, label, icon, color) in enumerate([
            ("susp_proc",  "Suspicious\nProcesses",  "⚠",  WARNING),
            ("susp_conn",  "Suspicious\nConnections","⛔", DANGER),
            ("total_proc", "Total\nProcesses",       "⚙",  ACCENT),
            ("uptime",     "System\nUptime",         "⏱",  SUCCESS),
        ]):
            cf = tk.Frame(sumrow, bg=CARD,
                           highlightbackground=BORDER, highlightthickness=1)
            cf.grid(row=0, column=col, padx=6, sticky="ew")
            pf = tk.Frame(cf, bg=CARD, padx=20, pady=18); pf.pack()
            tk.Label(pf, text=icon, font=(F, 22), bg=CARD, fg=color).pack()
            v = tk.StringVar(value="—")
            tk.Label(pf, textvariable=v, font=(F, 20, "bold"),
                     bg=CARD, fg=TEXT).pack(pady=(4,0))
            tk.Label(pf, text=label, font=(F, 9), bg=CARD, fg=MUTED,
                     justify="center").pack()
            self._sum_vars[key] = v

    def _make_feature_card(self, parent, icon, title, desc, page, col):
        outer = tk.Frame(parent, bg=CARD,
                          highlightbackground=BORDER, highlightthickness=1,
                          cursor="hand2")
        outer.grid(row=0, column=col, padx=10, sticky="nsew")
        inner = tk.Frame(outer, bg=CARD, padx=32, pady=40)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text=icon, font=(F, 32), bg=CARD, fg=ACCENT).pack(pady=(0,16))
        tk.Label(inner, text=title, font=(F, 16, "bold"), bg=CARD, fg=TEXT).pack()
        tk.Label(inner, text=desc, font=(F, 10), bg=CARD, fg=MUTED,
                 justify="center").pack(pady=(8,0))

        def on_enter(e):
            outer.configure(highlightbackground=ACCENT)
            inner.configure(bg=CARD2)
            for w in inner.winfo_children(): w.configure(bg=CARD2)
        def on_leave(e):
            outer.configure(highlightbackground=BORDER)
            inner.configure(bg=CARD)
            for w in inner.winfo_children(): w.configure(bg=CARD)
        def on_click(e): self.app._show_page(page)

        for w in (outer, inner):
            w.bind("<Enter>",    on_enter)
            w.bind("<Leave>",    on_leave)
            w.bind("<Button-1>", on_click)
        for child in inner.winfo_children():
            child.bind("<Enter>",    on_enter)
            child.bind("<Leave>",    on_leave)
            child.bind("<Button-1>", on_click)

    def on_show(self):
        threading.Thread(target=self._refresh_health, daemon=True).start()
        threading.Thread(target=self._refresh_threats, daemon=True).start()

    def auto_tick(self):
        self.on_show()

    def _refresh_health(self):
        try:
            h = get_system_health()
            self.after(0, lambda: self._apply_health(h))
        except: pass

    def _apply_health(self, h):
        self._cpu_bar["value"]  = h['cpu']
        self._mem_bar["value"]  = h['mem_percent']
        self._disk_bar["value"] = h['disk_percent']
        self._cpu_lbl.configure(text=f"{h['cpu']:.1f}%")
        self._mem_lbl.configure(
            text=f"{h['mem_percent']:.1f}%  —  {bytes_human(h['mem_used'])} / {bytes_human(h['mem_total'])}")
        self._disk_lbl.configure(
            text=f"{h['disk_percent']:.1f}%  —  {bytes_human(h['disk_used'])} / {bytes_human(h['disk_total'])}")
        self._net_lbl.configure(
            text=f"↑ {bytes_human(h['net_sent'])}   ↓ {bytes_human(h['net_recv'])}")

    def _refresh_threats(self):
        try:
            procs = get_processes()
            conns = get_network_connections()
            self.after(0, lambda: self._apply_threats(procs, conns))
        except: pass

    def _apply_threats(self, procs, conns):
        self._sum_vars["susp_proc"].set( str(sum(1 for p in procs if p['suspicious'])))
        self._sum_vars["susp_conn"].set( str(sum(1 for c in conns if c['suspicious'])))
        self._sum_vars["total_proc"].set(str(len(procs)))
        self._sum_vars["uptime"].set(    get_system_uptime())


# ═══════════════════════════════════════════════════════════════════════════════
#  PROCESSES PAGE
# ═══════════════════════════════════════════════════════════════════════════════
class ProcessesPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app
        self._all_procs = []
        self._build()

    def _build(self):
        # Page header
        hdr = tk.Frame(self, bg=CARD)
        hdr.pack(fill="x")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        hdr_inner = tk.Frame(hdr, bg=CARD, padx=24, pady=16)
        hdr_inner.pack(fill="x")
        tk.Label(hdr_inner, text="Process Monitor", font=(F, 18, "bold"),
                 bg=CARD, fg=TEXT).pack(side="left")
        tk.Label(hdr_inner, text="Monitor and manage running system processes",
                 font=(F, 10), bg=CARD, fg=MUTED).pack(side="left", padx=16)

        # Toolbar
        toolbar = tk.Frame(self, bg=BG, padx=24, pady=12)
        toolbar.pack(fill="x")

        # Search box
        search_frame = tk.Frame(toolbar, bg=CARD,
                                 highlightbackground=BORDER, highlightthickness=1)
        search_frame.pack(side="left")
        tk.Label(search_frame, text=" 🔍 ", font=(F,10),
                 bg=CARD, fg=MUTED).pack(side="left")
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._filter())
        tk.Entry(search_frame, textvariable=self._search_var,
                 bg=CARD, fg=TEXT, insertbackground=TEXT,
                 relief="flat", font=(F, 10), width=24,
                 highlightthickness=0).pack(side="left", padx=(0,8), ipady=5)

        # Threats only toggle
        self._threats_only = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(toolbar, text="Threats only",
                             variable=self._threats_only,
                             command=self._filter,
                             bg=BG, fg=MUTED,
                             selectcolor=CARD, activebackground=BG,
                             activeforeground=TEXT,
                             font=(F, 10))
        cb.pack(side="left", padx=16)

        # Action buttons
        btn_frame = tk.Frame(toolbar, bg=BG)
        btn_frame.pack(side="right")
        make_action_button(btn_frame, "↻  Refresh", self.refresh,
                           bg=ACCENT, fg=BG).pack(side="left", padx=4)
        make_action_button(btn_frame, "Export PDF", self._export_pdf,
                           bg=BTN_BG, fg=TEXT).pack(side="left", padx=4)

        # Stats strip
        stats = tk.Frame(self, bg=BG, padx=24)
        stats.pack(fill="x", pady=(0, 8))
        self._stat_vars = {
            "total": tk.StringVar(value="Total: —"),
            "susp":  tk.StringVar(value="Threats: —"),
            "sys":   tk.StringVar(value="System: —"),
        }
        for key, color in [("total", TEXT), ("susp", DANGER), ("sys", ACCENT)]:
            tk.Label(stats, textvariable=self._stat_vars[key],
                     font=(F, 9), bg=BG, fg=color).pack(side="left", padx=12)

        # Table
        tbl_outer = tk.Frame(self, bg=CARD,
                               highlightbackground=BORDER, highlightthickness=1)
        tbl_outer.pack(fill="both", expand=True, padx=24, pady=(0,12))
        cols  = ("PID","Name","CPU %","Mem %","Threads","Started","Status","Fix Suggestion")
        widths= [60, 180, 70, 70, 70, 80, 110, 340]
        self._tv = make_tree(tbl_outer, cols, widths, heights=26)
        for i, col in enumerate(cols):
            self._tv.heading(i, text=col,
                             command=lambda c=i: self._sort_col(c))
        self._tv.bind("<Double-1>",  self._show_details)
        self._tv.bind("<Button-3>",  self._ctx_show)

        self._ctx = tk.Menu(self, tearoff=0, bg=CARD, fg=TEXT,
                             activebackground=ACCENT_DIM,
                             activeforeground=TEXT, font=(F, 9))
        self._ctx.add_command(label="Kill Process",  command=self._kill_sel)
        self._ctx.add_command(label="Copy PID",      command=self._copy_pid)
        self._ctx.add_command(label="View Details",  command=self._show_details)

        # Status bar
        self._status_var = tk.StringVar(value="Ready")
        status_bar = tk.Frame(self, bg=CARD, pady=5)
        status_bar.pack(fill="x")
        tk.Label(status_bar, textvariable=self._status_var,
                 font=(F, 8), bg=CARD, fg=MUTED).pack(side="left", padx=16)

    def on_show(self):  self.refresh()
    def auto_tick(self): self.refresh()

    def refresh(self):
        self._status_var.set("Scanning processes…")
        threading.Thread(target=self._fetch, daemon=True).start()

    def _fetch(self):
        try:
            procs = get_processes()
            self.after(0, lambda: self._populate(procs))
        except Exception as e:
            self.after(0, lambda: self._status_var.set(f"Error: {e}"))

    def _populate(self, procs):
        self._all_procs = procs
        sp = sum(1 for p in procs if p['suspicious'])
        ss = sum(1 for p in procs if p['system_process'])
        self._stat_vars["total"].set(f"Total: {len(procs)}")
        self._stat_vars["susp"].set( f"Threats: {sp}")
        self._stat_vars["sys"].set(  f"System: {ss}")
        self._filter()
        self._status_var.set(
            f"Updated {datetime.now().strftime('%H:%M:%S')}  ·  "
            f"{len(procs)} processes  ·  {sp} threats detected")

    def _filter(self, *_):
        q  = self._search_var.get().lower()
        so = self._threats_only.get()
        for row in self._tv.get_children(): self._tv.delete(row)
        for i, p in enumerate(self._all_procs):
            if so and not p['suspicious']: continue
            if q and q not in f"{p['pid']} {p['name']} {p['cmdline']}".lower(): continue
            if p['suspicious']:
                tag    = "suspicious"
                status = "⚠ Suspicious"
            elif p['system_process']:
                tag    = "system"
                status = "● System"
            else:
                tag    = "odd" if i % 2 else "even"
                status = "✓ Clean"
            self._tv.insert("","end",
                values=(p['pid'], p['name'],
                        f"{p['cpu_percent']}%", f"{p['memory_percent']}%",
                        p['num_threads'], p['create_time'],
                        status, p['fix_suggestion'][:80] or ""),
                tags=(tag,), iid=str(p['pid']))

    def _sort_col(self, col):
        data = [(self._tv.set(k, col), k) for k in self._tv.get_children("")]
        try:   data.sort(key=lambda t: float(t[0].replace('%','')))
        except: data.sort()
        for i, (_, k) in enumerate(data): self._tv.move(k,"",i)

    def _ctx_show(self, e):
        item = self._tv.identify_row(e.y)
        if item: self._tv.selection_set(item); self._ctx.post(e.x_root, e.y_root)

    def _selected_pid(self):
        sel = self._tv.selection()
        if not sel: return None
        try: return int(self._tv.item(sel[0])['values'][0])
        except: return None

    def _kill_sel(self):
        pid = self._selected_pid()
        if pid is None: return
        name = self._tv.item(self._tv.selection()[0])['values'][1]
        if messagebox.askyesno("Kill Process",
                f"Terminate '{name}' (PID {pid})?\n\nThis cannot be undone.",
                icon="warning"):
            ok, msg = kill_process(pid)
            (messagebox.showinfo if ok else messagebox.showerror)(
                "Result", msg)
            if ok: self.refresh()

    def _copy_pid(self):
        pid = self._selected_pid()
        if pid: self.clipboard_clear(); self.clipboard_append(str(pid))

    def _show_details(self, *_):
        pid = self._selected_pid()
        if pid is None: return
        p = next((x for x in self._all_procs if x['pid']==pid), None)
        if not p: return
        win = tk.Toplevel(self, bg=BG)
        win.title(f"Process Details — {p['name']} (PID {pid})")
        win.geometry("620x420"); win.resizable(True, True)
        # Header
        hdr = tk.Frame(win, bg=CARD, pady=14, padx=20)
        hdr.pack(fill="x")
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x")
        tk.Label(hdr, text=p['name'], font=(F,14,"bold"), bg=CARD, fg=TEXT).pack(anchor="w")
        color = DANGER if p['suspicious'] else (ACCENT if p['system_process'] else SUCCESS)
        status = "⚠ Suspicious" if p['suspicious'] else ("● System" if p['system_process'] else "✓ Clean")
        tk.Label(hdr, text=status, font=(F,10), bg=CARD, fg=color).pack(anchor="w")
        # Fields
        body = tk.Frame(win, bg=BG, padx=20, pady=16); body.pack(fill="both", expand=True)
        fields = [
            ("PID",          str(p['pid'])),
            ("CPU Usage",    f"{p['cpu_percent']}%"),
            ("Memory Usage", f"{p['memory_percent']}%"),
            ("Threads",      str(p['num_threads'])),
            ("Parent PID",   str(p['ppid'])),
            ("Started",      p['create_time']),
            ("Type",         "System" if p['system_process'] else "User process"),
            ("Command Line", p['cmdline'][:300] or "N/A"),
            ("Fix Suggestion", p['fix_suggestion'] or "None"),
        ]
        for lbl, val in fields:
            row = tk.Frame(body, bg=BG); row.pack(fill="x", pady=3)
            tk.Label(row, text=lbl+":", width=16, anchor="e",
                     font=(F,9), bg=BG, fg=MUTED).pack(side="left")
            vc = DANGER if lbl=="Fix Suggestion" and val!="None" else TEXT
            tk.Label(row, text=val, anchor="w", wraplength=420,
                     font=(F,9), bg=BG, fg=vc).pack(side="left", padx=10)
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x")
        btn_row = tk.Frame(win, bg=CARD, pady=10, padx=20)
        btn_row.pack(fill="x")
        if p['suspicious']:
            make_action_button(btn_row, "Kill Process",
                               lambda: (win.destroy(), self._kill_sel()),
                               bg=DANGER, fg=TEXT).pack(side="left", padx=(0,8))
        make_action_button(btn_row, "Close", win.destroy,
                           bg=BTN_BG, fg=TEXT).pack(side="left")

    def _export_pdf(self):
        if not self._all_procs:
            messagebox.showwarning("No Data","Refresh first."); return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
            filetypes=[("PDF","*.pdf")],
            initialfile=f"processes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        if not path: return
        try:
            from reportlab.lib import colors as rc
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            doc = SimpleDocTemplate(path, pagesize=letter)
            styles = getSampleStyleSheet()
            content = [Paragraph(f"ProXDefend — Process Report  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Title']), Spacer(1,12)]
            data = [["PID","Name","CPU%","Mem%","Threads","Status","Fix Suggestion"]]
            for p in self._all_procs:
                data.append([str(p['pid']),p['name'],f"{p['cpu_percent']}%",
                              f"{p['memory_percent']}%",str(p['num_threads']),
                              "SUSPICIOUS" if p['suspicious'] else "Clean",
                              (p['fix_suggestion'] or "")[:60]])
            t = Table(data, colWidths=[.5*inch,1.5*inch,.6*inch,.6*inch,.6*inch,.9*inch,2.7*inch])
            ts = TableStyle([
                ('BACKGROUND',(0,0),(-1,0),rc.HexColor("#161b22")),
                ('TEXTCOLOR',(0,0),(-1,0),rc.HexColor("#58a6ff")),
                ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
                ('GRID',(0,0),(-1,-1),.4,rc.HexColor("#30363d")),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[rc.white, rc.HexColor("#f6f8fa")]),
                ('FONTSIZE',(0,0),(-1,-1),8),
            ])
            for i, p in enumerate(self._all_procs, 1):
                if p['suspicious']:
                    ts.add('BACKGROUND',(0,i),(-1,i),rc.HexColor("#ffd6d4"))
            t.setStyle(ts); content.append(t)
            doc.build(content)
            messagebox.showinfo("Exported", f"Saved to:\n{path}")
        except ImportError:
            messagebox.showerror("Missing Library","pip install reportlab")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK PAGE
# ═══════════════════════════════════════════════════════════════════════════════
class NetworkPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app
        self._all_conns = []
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=CARD)
        hdr.pack(fill="x")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        hdr_inner = tk.Frame(hdr, bg=CARD, padx=24, pady=16)
        hdr_inner.pack(fill="x")
        tk.Label(hdr_inner, text="Network Monitor", font=(F,18,"bold"),
                 bg=CARD, fg=TEXT).pack(side="left")
        tk.Label(hdr_inner, text="Monitor active connections and detect threats",
                 font=(F,10), bg=CARD, fg=MUTED).pack(side="left", padx=16)

        # Toolbar
        toolbar = tk.Frame(self, bg=BG, padx=24, pady=12)
        toolbar.pack(fill="x")
        sf = tk.Frame(toolbar, bg=CARD,
                       highlightbackground=BORDER, highlightthickness=1)
        sf.pack(side="left")
        tk.Label(sf, text=" 🔍 ", font=(F,10), bg=CARD, fg=MUTED).pack(side="left")
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._filter())
        tk.Entry(sf, textvariable=self._search_var, bg=CARD, fg=TEXT,
                 insertbackground=TEXT, relief="flat", font=(F,10), width=24,
                 highlightthickness=0).pack(side="left", padx=(0,8), ipady=5)
        self._threats_only = tk.BooleanVar(value=False)
        tk.Checkbutton(toolbar, text="Threats only",
                        variable=self._threats_only, command=self._filter,
                        bg=BG, fg=MUTED, selectcolor=CARD,
                        activebackground=BG, activeforeground=TEXT,
                        font=(F,10)).pack(side="left", padx=16)
        btn_frame = tk.Frame(toolbar, bg=BG); btn_frame.pack(side="right")
        make_action_button(btn_frame, "↻  Refresh", self.refresh, bg=ACCENT, fg=BG).pack(side="left", padx=4)
        make_action_button(btn_frame, "Export PDF", self._export_pdf, bg=BTN_BG, fg=TEXT).pack(side="left", padx=4)

        # Stats strip + I/O
        stats = tk.Frame(self, bg=BG, padx=24); stats.pack(fill="x", pady=(0,8))
        self._stat_vars = {k: tk.StringVar(value=v) for k, v in
                           [("total","Total: —"),("susp","Threats: —"),
                            ("listen","Listening: —"),("io","I/O: —")]}
        for key, color in [("total",TEXT),("susp",DANGER),("listen",ACCENT),("io",SUCCESS)]:
            tk.Label(stats, textvariable=self._stat_vars[key],
                     font=(F,9), bg=BG, fg=color).pack(side="left", padx=12)

        # Table
        tbl_outer = tk.Frame(self, bg=CARD,
                               highlightbackground=BORDER, highlightthickness=1)
        tbl_outer.pack(fill="both", expand=True, padx=24, pady=(0,12))
        cols   = ("PID","Process","Local Address","Remote Address","Status","Threat","Reason")
        widths = [65, 155, 170, 170, 100, 90, 290]
        self._tv = make_tree(tbl_outer, cols, widths, heights=24)
        self._tv.bind("<Double-1>", self._show_details)
        self._tv.bind("<Button-3>", self._ctx_show)

        self._ctx = tk.Menu(self, tearoff=0, bg=CARD, fg=TEXT,
                             activebackground=ACCENT_DIM,
                             activeforeground=TEXT, font=(F,9))
        self._ctx.add_command(label="View Details",   command=self._show_details)
        self._ctx.add_command(label="Block (Admin)",  command=self._block_conn)

        self._status_var = tk.StringVar(value="Ready")
        status_bar = tk.Frame(self, bg=CARD, pady=5); status_bar.pack(fill="x")
        tk.Label(status_bar, textvariable=self._status_var,
                 font=(F,8), bg=CARD, fg=MUTED).pack(side="left", padx=16)

    def on_show(self):   self.refresh()
    def auto_tick(self): self.refresh()

    def refresh(self):
        self._status_var.set("Scanning connections…")
        threading.Thread(target=self._fetch, daemon=True).start()

    def _fetch(self):
        try:
            conns = get_network_connections()
            net   = psutil.net_io_counters()
            self.after(0, lambda: self._populate(conns, net))
        except Exception as e:
            self.after(0, lambda: self._status_var.set(f"Error: {e}"))

    def _populate(self, conns, net):
        self._all_conns = conns
        sp = sum(1 for c in conns if c['suspicious'])
        sl = sum(1 for c in conns if c['status']=='LISTEN')
        self._stat_vars["total"].set( f"Total: {len(conns)}")
        self._stat_vars["susp"].set(  f"Threats: {sp}")
        self._stat_vars["listen"].set(f"Listening: {sl}")
        self._stat_vars["io"].set(
            f"↑ {bytes_human(net.bytes_sent)}  ↓ {bytes_human(net.bytes_recv)}")
        self._filter()
        self._status_var.set(
            f"Updated {datetime.now().strftime('%H:%M:%S')}  ·  "
            f"{len(conns)} connections  ·  {sp} threats")

    def _filter(self, *_):
        q  = self._search_var.get().lower()
        so = self._threats_only.get()
        for row in self._tv.get_children(): self._tv.delete(row)
        for i, c in enumerate(self._all_conns):
            if so and not c['suspicious']: continue
            if q and q not in f"{c['pid']} {c['process_name']} {c['laddr']} {c['raddr']}".lower(): continue
            tag = "suspicious" if c['suspicious'] else ("odd" if i%2 else "even")
            self._tv.insert("","end",
                values=(c['pid'] or "—", c['process_name'],
                        c['laddr'], c['raddr'], c['status'],
                        "⚠ Yes" if c['suspicious'] else "✓ No",
                        "; ".join(c['reasons']) or ""),
                tags=(tag,), iid=str(i))

    def _ctx_show(self, e):
        item = self._tv.identify_row(e.y)
        if item: self._tv.selection_set(item); self._ctx.post(e.x_root, e.y_root)

    def _selected_conn(self):
        sel = self._tv.selection()
        if not sel: return None
        try: idx=int(sel[0]); return self._all_conns[idx] if idx<len(self._all_conns) else None
        except: return None

    def _show_details(self, *_):
        c = self._selected_conn()
        if not c: return
        win = tk.Toplevel(self, bg=BG)
        win.title(f"Connection Details — PID {c['pid']}")
        win.geometry("580x360")
        hdr = tk.Frame(win, bg=CARD, pady=14, padx=20); hdr.pack(fill="x")
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x")
        tk.Label(hdr, text=f"{c['process_name']}  —  Connection Details",
                 font=(F,13,"bold"), bg=CARD, fg=TEXT).pack(anchor="w")
        color  = DANGER if c['suspicious'] else SUCCESS
        status = "⚠ Suspicious" if c['suspicious'] else "✓ Clean"
        tk.Label(hdr, text=status, font=(F,10), bg=CARD, fg=color).pack(anchor="w")
        body = tk.Frame(win, bg=BG, padx=20, pady=16); body.pack(fill="both", expand=True)
        for lbl, val, vc in [
            ("PID",           str(c['pid']),        TEXT),
            ("Process",       c['process_name'],    TEXT),
            ("Local Address", c['laddr'],           ACCENT),
            ("Remote Address",c['raddr'],           TEXT),
            ("Status",        c['status'],          TEXT),
            ("Suspicious",    status,               color),
            ("Reason(s)",     "; ".join(c['reasons']) or "None", WARNING if c['reasons'] else MUTED),
            ("Fix Suggestion",c['fix_suggestion'] or "None",     MUTED),
        ]:
            row = tk.Frame(body, bg=BG); row.pack(fill="x", pady=3)
            tk.Label(row, text=lbl+":", width=16, anchor="e",
                     font=(F,9), bg=BG, fg=MUTED).pack(side="left")
            tk.Label(row, text=val, anchor="w", wraplength=380,
                     font=(F,9), bg=BG, fg=vc).pack(side="left", padx=10)
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x")
        btn_row = tk.Frame(win, bg=CARD, pady=10, padx=20); btn_row.pack(fill="x")
        make_action_button(btn_row, "Close", win.destroy, bg=BTN_BG, fg=TEXT).pack(side="left")

    def _block_conn(self):
        c = self._selected_conn()
        if not c or not c['pid']: return
        try:
            proc = psutil.Process(c['pid']); exe = proc.exe()
            rule = f"ProXDefend_Block_{os.path.basename(exe)}_{c['pid']}"
            cmd  = f'netsh advfirewall firewall add rule name="{rule}" dir=out program="{exe}" action=block'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Blocked", f"Outbound blocked for:\n{exe}")
            else:
                messagebox.showerror("Failed", result.stderr or "Failed — admin rights required?")
        except Exception as e: messagebox.showerror("Error", str(e))

    def _export_pdf(self):
        if not self._all_conns: messagebox.showwarning("No Data","Refresh first."); return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
            filetypes=[("PDF","*.pdf")],
            initialfile=f"network_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        if not path: return
        try:
            from reportlab.lib import colors as rc
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            doc = SimpleDocTemplate(path, pagesize=letter)
            styles = getSampleStyleSheet()
            content = [Paragraph(f"ProXDefend — Network Report  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Title']), Spacer(1,12)]
            data = [["PID","Process","Local","Remote","Status","Suspicious","Reason"]]
            for c in self._all_conns:
                data.append([str(c['pid'] or ""),c['process_name'],
                              c['laddr'],c['raddr'],c['status'],
                              "YES" if c['suspicious'] else "No",
                              "; ".join(c['reasons'])[:60]])
            t = Table(data, colWidths=[.5*inch,1.2*inch,1.4*inch,1.4*inch,.7*inch,.7*inch,1.8*inch])
            ts = TableStyle([
                ('BACKGROUND',(0,0),(-1,0),rc.HexColor("#161b22")),
                ('TEXTCOLOR',(0,0),(-1,0),rc.HexColor("#58a6ff")),
                ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
                ('GRID',(0,0),(-1,-1),.4,rc.HexColor("#30363d")),
                ('ROWBACKGROUNDS',(0,1),(-1,-1),[rc.white,rc.HexColor("#f6f8fa")]),
                ('FONTSIZE',(0,0),(-1,-1),8),
            ])
            for i,c in enumerate(self._all_conns,1):
                if c['suspicious']: ts.add('BACKGROUND',(0,i),(-1,i),rc.HexColor("#ffd6d4"))
            t.setStyle(ts); content.append(t)
            doc.build(content)
            messagebox.showinfo("Exported", f"Saved to:\n{path}")
        except ImportError: messagebox.showerror("Missing Library","pip install reportlab")
        except Exception as e: messagebox.showerror("Export Failed", str(e))


# ═══════════════════════════════════════════════════════════════════════════════
#  SCANNER PAGE
# ═══════════════════════════════════════════════════════════════════════════════
class ScannerPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app
        self._history = []
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=CARD); hdr.pack(fill="x")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        hdr_inner = tk.Frame(hdr, bg=CARD, padx=24, pady=16); hdr_inner.pack(fill="x")
        tk.Label(hdr_inner, text="File Scanner", font=(F,18,"bold"),
                 bg=CARD, fg=TEXT).pack(side="left")
        tk.Label(hdr_inner, text="Upload and scan files for potential threats",
                 font=(F,10), bg=CARD, fg=MUTED).pack(side="left", padx=16)

        # Body with two columns
        body = tk.Frame(self, bg=BG); body.pack(fill="both", expand=True)
        left  = tk.Frame(body, bg=BG); left.pack(side="left", fill="both", expand=True)
        right = tk.Frame(body, bg=BG, width=380); right.pack(side="right", fill="y", padx=(0,24))
        right.pack_propagate(False)

        # ── Upload / scan card ────────────────────────────────────────────────
        upload_card = tk.Frame(left, bg=CARD,
                                highlightbackground=BORDER, highlightthickness=1)
        upload_card.pack(fill="x", padx=24, pady=16)
        uc_inner = tk.Frame(upload_card, bg=CARD, padx=28, pady=36)
        uc_inner.pack(fill="x")

        # Shield icon  (drawn with canvas — no emoji font needed)
        icon_cv = tk.Canvas(uc_inner, width=64, height=64, bg=CARD, highlightthickness=0)
        icon_cv.pack(pady=(0,14))
        # Shield shape
        pts = [32,4, 56,14, 56,36, 32,60, 8,36, 8,14]
        icon_cv.create_polygon(pts, fill=ACCENT_DIM, outline=ACCENT, width=2, smooth=False)
        icon_cv.create_text(32,34, text="✓", font=(F,18,"bold"), fill=ACCENT)

        tk.Label(uc_inner, text="Select a file to scan",
                 font=(F,14,"bold"), bg=CARD, fg=TEXT).pack()
        tk.Label(uc_inner,
                 text="Supports all file types  ·  SHA-256 hash  ·  Entropy analysis  ·  Pattern matching",
                 font=(F,9), bg=CARD, fg=MUTED).pack(pady=(6,0))

        btn_row = tk.Frame(uc_inner, bg=CARD); btn_row.pack(pady=18)
        make_action_button(btn_row, "  Choose File  ",
                           self._choose_file, bg=ACCENT, fg=BG).pack(side="left", padx=6)
        make_action_button(btn_row, "  Clear  ",
                           self._clear, bg=BTN_BG, fg=TEXT).pack(side="left", padx=6)

        self._file_label = tk.Label(uc_inner, text="No file selected",
                                     font=(F,9,"italic"), bg=CARD, fg=MUTED)
        self._file_label.pack()

        # Progress bar
        self._prog_bar = ttk.Progressbar(left, length=500, mode="indeterminate",
                                          style="App.Horizontal.TProgressbar")
        self._prog_bar.pack(pady=(4,0), padx=24)
        self._prog_label = tk.Label(left, text="", font=(F,9), bg=BG, fg=MUTED)
        self._prog_label.pack()

        # ── Result card ───────────────────────────────────────────────────────
        result_outer = tk.Frame(left, bg=CARD,
                                 highlightbackground=BORDER, highlightthickness=1)
        result_outer.pack(fill="x", padx=24, pady=8)
        self._result_frame = tk.Frame(result_outer, bg=CARD, padx=24, pady=18)
        self._result_frame.pack(fill="x")

        # Verdict row
        vrow = tk.Frame(self._result_frame, bg=CARD); vrow.pack(fill="x")
        self._verdict_icon_lbl = tk.Label(vrow, text="◈", font=(F,24),
                                           bg=CARD, fg=MUTED)
        self._verdict_icon_lbl.pack(side="left")
        self._verdict_var = tk.StringVar(value="No scan yet")
        self._verdict_lbl = tk.Label(vrow, textvariable=self._verdict_var,
                                      font=(F,16,"bold"), bg=CARD, fg=MUTED)
        self._verdict_lbl.pack(side="left", padx=12)

        # Metadata chips
        meta_row = tk.Frame(self._result_frame, bg=CARD); meta_row.pack(fill="x", pady=10)
        self._meta_vars = {}
        for key, label in [("File","File"),("Hash","SHA-256"),("Size","Size"),("Type","Type")]:
            chip = tk.Frame(meta_row, bg=CARD2,
                             highlightbackground=BORDER, highlightthickness=1)
            chip.pack(side="left", padx=(0,10))
            tk.Label(chip, text=f" {label} ", font=(F,7,"bold"),
                     bg=CARD2, fg=MUTED).pack(anchor="w", padx=6, pady=(4,0))
            v = tk.StringVar(value="—")
            tk.Label(chip, textvariable=v, font=(F,9),
                     bg=CARD2, fg=TEXT).pack(anchor="w", padx=6, pady=(0,4))
            self._meta_vars[key] = v

        # Scan log
        tk.Label(self._result_frame, text="Scan Details",
                 font=(F,10,"bold"), bg=CARD, fg=TEXT).pack(anchor="w", pady=(6,4))
        self._log = scrolledtext.ScrolledText(
            self._result_frame, height=7, bg=BG, fg=TEXT,
            font=("Courier New", 9), relief="flat",
            state="disabled", insertbackground=TEXT,
            selectbackground=ACCENT_DIM)
        self._log.pack(fill="x")

        # ── History panel ─────────────────────────────────────────────────────
        tk.Label(right, text="Scan History", font=(F,12,"bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", pady=(16,8))
        hist_outer = tk.Frame(right, bg=CARD,
                               highlightbackground=BORDER, highlightthickness=1)
        hist_outer.pack(fill="both", expand=True)
        hist_cols = ("File","Verdict","Size","Time")
        self._hist_tv = make_tree(hist_outer, hist_cols,
                                   [160,130,70,80], heights=28)

    def on_show(self):   pass
    def auto_tick(self): pass

    def _choose_file(self):
        path = filedialog.askopenfilename(title="Select File to Scan")
        if not path: return
        self._file_label.configure(text=f"📄  {os.path.basename(path)}", fg=TEXT)
        self._scan(path)

    def _clear(self):
        self._file_label.configure(text="No file selected", fg=MUTED)
        self._verdict_var.set("No scan yet")
        self._verdict_lbl.configure(fg=MUTED)
        self._verdict_icon_lbl.configure(text="◈", fg=MUTED)
        for v in self._meta_vars.values(): v.set("—")
        self._log.configure(state="normal")
        self._log.delete("1.0","end")
        self._log.configure(state="disabled")

    def _scan(self, path):
        self._prog_label.configure(text="Scanning — please wait…")
        self._prog_bar.start(10)
        self._verdict_var.set("Scanning…")
        self._verdict_lbl.configure(fg=MUTED)
        def run():
            result = scan_file(path)
            self.after(0, lambda: self._show_result(path, result))
        threading.Thread(target=run, daemon=True).start()

    def _show_result(self, path, result):
        self._prog_bar.stop()
        self._prog_label.configure(text="Scan complete")

        verdict = result["verdict"]
        if "Malicious" in verdict:    color, icon = DANGER,  "✖"
        elif "Suspicious" in verdict: color, icon = WARNING, "⚠"
        elif "Clean" in verdict:      color, icon = SUCCESS, "✔"
        else:                          color, icon = MUTED,   "?"

        self._verdict_var.set(verdict)
        self._verdict_lbl.configure(fg=color)
        self._verdict_icon_lbl.configure(text=icon, fg=color)

        h = result.get("hash","") or ""
        self._meta_vars["File"].set(os.path.basename(path))
        self._meta_vars["Hash"].set(h[:32]+"…" if len(h)>32 else h or "N/A")
        self._meta_vars["Size"].set(result.get("file_size","N/A"))
        self._meta_vars["Type"].set(result.get("file_type","N/A"))

        self._log.configure(state="normal")
        self._log.delete("1.0","end")
        self._log.tag_configure("ok",   foreground=SUCCESS)
        self._log.tag_configure("bad",  foreground=DANGER)
        self._log.tag_configure("warn", foreground=WARNING)
        self._log.tag_configure("info", foreground=ACCENT)
        if result["details"]:
            for d in result["details"]:
                tag = "bad" if any(x in d for x in ["Pattern","keyword","entropy"]) else "info"
                self._log.insert("end", f"  • {d}\n", tag)
        else:
            self._log.insert("end","  • No threats detected.\n","ok")
        if result.get("patterns"):
            self._log.insert("end",
                f"\n  Patterns matched: {', '.join(result['patterns'])}\n","warn")
        self._log.configure(state="disabled")

        # Add to history
        entry = {"file": os.path.basename(path), "verdict": verdict,
                 "size": result.get("file_size",""), "time": datetime.now().strftime("%H:%M:%S")}
        self._history.insert(0, entry)
        self._hist_tv.insert("","0",
            values=(entry["file"],entry["verdict"],entry["size"],entry["time"]))
        tag = "suspicious" if "Malicious" in verdict or "Suspicious" in verdict else "clean"
        self._hist_tv.item(self._hist_tv.get_children()[0], tags=(tag,))



# ═══════════════════════════════════════════════════════════════════════════════
#  ALERTS PAGE
# ═══════════════════════════════════════════════════════════════════════════════
class AlertsPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app
        self._build()

    def _build(self):
        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=CARD)
        hdr.pack(fill="x")
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        hdr_inner = tk.Frame(hdr, bg=CARD, padx=24, pady=14)
        hdr_inner.pack(fill="x")
        tk.Label(hdr_inner, text="🔔  Alerts Center",
                 font=(F, 18, "bold"), bg=CARD, fg=TEXT).pack(side="left")
        tk.Label(hdr_inner, text="Real-time threat notifications from process and network monitoring",
                 font=(F, 10), bg=CARD, fg=MUTED).pack(side="left", padx=16)

        # ── Controls bar ──────────────────────────────────────────────────────
        ctrl = tk.Frame(self, bg=BG, padx=24, pady=10)
        ctrl.pack(fill="x")

        # Filter dropdown
        tk.Label(ctrl, text="Filter:", font=(F, 10),
                 bg=BG, fg=MUTED).pack(side="left")
        self._filter_var = tk.StringVar(value="All")
        filter_menu = ttk.Combobox(ctrl, textvariable=self._filter_var,
                                    values=["All","Critical","Warning","Info",
                                            "Process","Network","System"],
                                    state="readonly", width=12,
                                    font=(F, 9))
        filter_menu.pack(side="left", padx=(6,16))
        filter_menu.bind("<<ComboboxSelected>>", lambda e: self._refresh_list())

        # Alert enable toggle
        self._enabled_var = tk.BooleanVar(value=True)
        tk.Checkbutton(ctrl, text="Monitoring Active",
                       variable=self._enabled_var,
                       command=self._toggle_monitoring,
                       bg=BG, fg=SUCCESS, selectcolor=CARD,
                       activebackground=BG, activeforeground=SUCCESS,
                       font=(F, 10, "bold")).pack(side="left")

        # Sound toggle
        self._sound_var = tk.BooleanVar(value=True)
        tk.Checkbutton(ctrl, text="Sound",
                       variable=self._sound_var,
                       command=self._toggle_sound,
                       bg=BG, fg=MUTED, selectcolor=CARD,
                       activebackground=BG, font=(F, 10)).pack(side="left", padx=12)

        # Right buttons
        btn_r = tk.Frame(ctrl, bg=BG); btn_r.pack(side="right")
        make_action_button(btn_r, "↻  Refresh",     self._refresh_list,
                           bg=ACCENT,   fg=BG).pack(side="left", padx=4)
        make_action_button(btn_r, "Mark All Read",  self._mark_read,
                           bg=BTN_BG,  fg=TEXT).pack(side="left", padx=4)
        make_action_button(btn_r, "📧  Email Setup", self._open_email_settings,
                           bg="#1f4068", fg=TEXT).pack(side="left", padx=4)
        make_action_button(btn_r, "🗑  Clear All",   self._clear_all,
                           bg=BTN_BG,  fg=DANGER).pack(side="left", padx=4)

        # ── Stats strip ───────────────────────────────────────────────────────
        stats = tk.Frame(self, bg=BG, padx=24, pady=4)
        stats.pack(fill="x")
        self._stat_vars = {k: tk.StringVar(value=v) for k, v in [
            ("total",   "Total: 0"),
            ("critical","Critical: 0"),
            ("warning", "Warning: 0"),
            ("unread",  "Unread: 0"),
        ]}
        for key, color in [("total",TEXT),("critical",DANGER),
                            ("warning",WARNING),("unread",ACCENT)]:
            tk.Label(stats, textvariable=self._stat_vars[key],
                     font=(F, 9), bg=BG, fg=color).pack(side="left", padx=12)

        # ── Alerts table ──────────────────────────────────────────────────────
        tbl_outer = tk.Frame(self, bg=CARD,
                              highlightbackground=BORDER, highlightthickness=1)
        tbl_outer.pack(fill="both", expand=True, padx=24, pady=(4,0))

        cols   = ("Time","Date","Level","Category","Title","Message","Detail")
        widths = [70, 90, 80, 90, 200, 300, 250]
        self._tv = make_tree(tbl_outer, cols, widths, heights=24)
        self._tv.tag_configure("critical", foreground=DANGER,  background="#1e0e0d")
        self._tv.tag_configure("warning",  foreground=WARNING, background="#1e1500")
        self._tv.tag_configure("info",     foreground=ACCENT)
        self._tv.tag_configure("unread",   font=(F, 9, "bold"))
        self._tv.bind("<Double-1>", self._show_detail)

        # ── Status bar ────────────────────────────────────────────────────────
        self._status_var = tk.StringVar(value="Monitoring active — checking every 10 seconds")
        status_bar = tk.Frame(self, bg=CARD, pady=5)
        status_bar.pack(fill="x")
        self._status_dot = tk.Label(status_bar, text=" ● ", font=(F, 7),
                                     bg=CARD, fg=SUCCESS)
        self._status_dot.pack(side="left")
        tk.Label(status_bar, textvariable=self._status_var,
                 font=(F, 8), bg=CARD, fg=MUTED).pack(side="left")

        # Subscribe to the alert engine
        self.app._alert_engine.subscribe(lambda a: self.after(0, self._on_new_alert))

    def on_show(self):
        self.app._alert_engine.mark_all_read()
        self.app._on_alert(None)   # refresh badge
        self._refresh_list()

    def auto_tick(self):
        self._refresh_list()

    def _refresh_list(self):
        alerts = self.app._alert_engine.get_alerts()
        filt   = self._filter_var.get()

        # Filter
        if filt != "All":
            if filt in ("Critical","Warning","Info"):
                alerts = [a for a in alerts if a["level"].capitalize() == filt]
            else:
                alerts = [a for a in alerts if a.get("category","").lower() == filt.lower()]

        # Stats
        all_alerts = self.app._alert_engine.get_alerts()
        self._stat_vars["total"].set(   f"Total: {len(all_alerts)}")
        self._stat_vars["critical"].set(f"Critical: {sum(1 for a in all_alerts if a['level']=='critical')}")
        self._stat_vars["warning"].set( f"Warning:  {sum(1 for a in all_alerts if a['level']=='warning')}")
        self._stat_vars["unread"].set(  f"Unread: {self.app._alert_engine.unread_count()}")

        # Repopulate table
        for row in self._tv.get_children():
            self._tv.delete(row)

        for i, a in enumerate(alerts):
            icon = ALERT_LEVELS.get(a["level"], ALERT_LEVELS["info"])["icon"]
            tags = [a["level"]]
            if not a.get("read"):
                tags.append("unread")
            self._tv.insert("","end",
                values=(a["time"], a["date"],
                        icon + " " + a["level"].capitalize(),
                        a.get("category",""),
                        a.get("title",""),
                        a.get("message",""),
                        a.get("detail","")),
                tags=tuple(tags))

        monitoring = self._enabled_var.get()
        self._status_var.set(
            "Monitoring active — checking every 10 seconds"
            if monitoring else "⚠ Monitoring is PAUSED")
        self._status_dot.configure(fg=SUCCESS if monitoring else WARNING)

    def _on_new_alert(self):
        self._refresh_list()

    def _toggle_monitoring(self):
        self.app._alert_engine.set_enabled(self._enabled_var.get())
        self._refresh_list()

    def _toggle_sound(self):
        self.app._alert_engine.set_sound(self._sound_var.get())

    def _mark_read(self):
        self.app._alert_engine.mark_all_read()
        self.app._on_alert(None)
        self._refresh_list()

    def _clear_all(self):
        if messagebox.askyesno("Clear Alerts",
                "Clear all alerts?\n\nThis cannot be undone."):
            self.app._alert_engine.clear_alerts()
            self._refresh_list()

    def _open_email_settings(self):
        """Automatic Email Setup Wizard — just enter email + password."""
        notifier = self.app._alert_engine.email
        cfg      = notifier.cfg

        win = tk.Toplevel(self, bg=BG)
        win.title("Email Notification Setup")
        win.geometry("520x660")
        win.resizable(True, True)
        win.grab_set()

        # ── Header ────────────────────────────────────────────────────────────
        hdr = tk.Frame(win, bg=CARD, pady=16, padx=24); hdr.pack(fill="x")
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x")
        tk.Label(hdr, text="📧  Automatic Email Setup",
                 font=(F, 14, "bold"), bg=CARD, fg=TEXT).pack(anchor="w")
        tk.Label(hdr,
                 text="ProXDefend detects your email provider automatically.",
                 font=(F, 9), bg=CARD, fg=MUTED).pack(anchor="w", pady=(2,0))

        # ── Bottom buttons (packed first so they are always visible) ──────────
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", side="bottom")
        btn_row = tk.Frame(win, bg=CARD, pady=12, padx=24)
        btn_row.pack(fill="x", side="bottom")
        status_lbl_outer = tk.Frame(win, bg=BG)
        status_lbl_outer.pack(fill="x", side="bottom", padx=28)

        body = tk.Frame(win, bg=BG, padx=28, pady=12)
        body.pack(fill="both", expand=True)

        # ── Enable toggle ─────────────────────────────────────────────────────
        enabled_var = tk.BooleanVar(value=cfg.get("enabled", False))
        top_row = tk.Frame(body, bg=BG); top_row.pack(fill="x", pady=(0,14))
        tk.Checkbutton(top_row, text="  Enable Email Notifications",
                       variable=enabled_var,
                       bg=BG, fg=SUCCESS, selectcolor=CARD,
                       activebackground=BG, activeforeground=SUCCESS,
                       font=(F, 11, "bold")).pack(side="left")

        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(0,16))

        # ── Provider badge (auto-updates as user types) ───────────────────────
        provider_var = tk.StringVar(value="")
        provider_row = tk.Frame(body, bg=BG); provider_row.pack(fill="x", pady=(0,10))
        tk.Label(provider_row, text="Detected Provider:", font=(F,9),
                 bg=BG, fg=MUTED).pack(side="left")
        provider_lbl = tk.Label(provider_row, textvariable=provider_var,
                                 font=(F, 9, "bold"), bg=BG, fg=ACCENT)
        provider_lbl.pack(side="left", padx=8)

        # ── 3 simple fields ───────────────────────────────────────────────────
        def make_field(parent, label, key, placeholder, show=""):
            f = tk.Frame(parent, bg=BG); f.pack(fill="x", pady=7)
            tk.Label(f, text=label, font=(F, 9), bg=BG, fg=MUTED,
                     anchor="w").pack(fill="x")
            var = tk.StringVar(value=cfg.get(key, ""))
            kw  = {"show": show} if show else {}
            ent = tk.Entry(f, textvariable=var, bg=CARD, fg=TEXT,
                           insertbackground=ACCENT, font=(F, 11),
                           relief="flat",
                           highlightbackground=BORDER,
                           highlightthickness=1, width=40, **kw)
            ent.pack(fill="x", ipady=7, pady=(4, 0))
            if not cfg.get(key):
                ent.insert(0, placeholder)
                ent.config(fg=MUTED)
                def on_in(e, e2=ent, p=placeholder):
                    if e2.get() == p: e2.delete(0, "end"); e2.config(fg=TEXT)
                def on_out(e, e2=ent, p=placeholder):
                    if not e2.get(): e2.insert(0, p); e2.config(fg=MUTED)
                ent.bind("<FocusIn>",  on_in)
                ent.bind("<FocusOut>", on_out)
            return var, ent

        sender_var,   sender_ent   = make_field(body, "Your Email Address",
                                                "sender_email",
                                                "yourname@gmail.com  /  outlook.com  /  yahoo.com  …")
        password_var, password_ent = make_field(body, "App Password  (see instructions below)",
                                                "sender_password",
                                                "Enter app password here", show="*")
        receiver_var, receiver_ent = make_field(body, "Send Alerts To  (receiver email)",
                                                "receiver_email",
                                                "receiver@anyemail.com")

        # Update provider badge on email typing
        def on_email_change(*_):
            email = sender_var.get().strip()
            if "@" in email and "." in email.split("@")[-1]:
                h, p, _ = EmailNotifier.detect_smtp(email)
                domain  = email.split("@")[-1].lower()
                names   = {
                    "gmail.com":"Gmail","googlemail.com":"Gmail",
                    "outlook.com":"Outlook","hotmail.com":"Outlook","live.com":"Outlook",
                    "yahoo.com":"Yahoo","ymail.com":"Yahoo",
                    "icloud.com":"iCloud","me.com":"iCloud",
                    "zoho.com":"Zoho","protonmail.com":"ProtonMail","proton.me":"ProtonMail",
                }
                name = names.get(domain, domain.split(".")[0].capitalize())
                provider_var.set(f"✔  {name}  ({h}:{p})")
                provider_lbl.configure(fg=SUCCESS)
            else:
                provider_var.set("Type your email above to detect provider")
                provider_lbl.configure(fg=MUTED)

        sender_var.trace_add("write", on_email_change)
        on_email_change()   # set initial state

        # ── Alert level checkboxes ────────────────────────────────────────────
        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(12,8))
        lvl_row = tk.Frame(body, bg=BG); lvl_row.pack(fill="x")
        tk.Label(lvl_row, text="Email me for:", font=(F,9), bg=BG, fg=MUTED).pack(side="left")
        send_on  = cfg.get("send_on", ["critical","warning"])
        crit_var = tk.BooleanVar(value="critical" in send_on)
        warn_var = tk.BooleanVar(value="warning"  in send_on)
        info_var = tk.BooleanVar(value="info"     in send_on)
        for var, lbl, color in [(crit_var,"🔴 Critical",DANGER),
                                 (warn_var,"🟡 Warning",WARNING),
                                 (info_var,"🔵 Info",ACCENT)]:
            tk.Checkbutton(lvl_row, text=lbl, variable=var, bg=BG, fg=color,
                           selectcolor=CARD, activebackground=BG,
                           font=(F, 9)).pack(side="left", padx=10)

        # ── Instructions panel ────────────────────────────────────────────────
        note = tk.Frame(body, bg=CARD2,
                        highlightbackground=BORDER, highlightthickness=1)
        note.pack(fill="x", pady=(14,0))
        note_inner = tk.Frame(note, bg=CARD2, padx=14, pady=10)
        note_inner.pack(fill="x")

        # Dynamic instructions based on provider
        instr_var = tk.StringVar(value="")
        INSTRUCTIONS = {
            "Gmail":   "Gmail: myaccount.google.com -> Security -> 2-Step Verification -> App Passwords -> Create -> copy the 16-char password into App Password above.",
            "Outlook": "Outlook/Hotmail: account.microsoft.com/security -> Advanced Security -> App Passwords -> Create -> copy the password above.",
            "Yahoo":   "Yahoo: login.yahoo.com -> Account Security -> 2-Step Verification -> App Password -> Generate -> copy the password above.",
            "iCloud":  "iCloud: appleid.apple.com -> Sign-In & Security -> App-Specific Passwords -> Generate -> copy the password above.",
            "default": "1. Enable 2-Step Verification on your email account.  2. Go to your account security settings and generate an App Password.  3. Paste it into the App Password field above.  (Do NOT use your regular login password)",
        }
        def update_instructions(*_):
            email = sender_var.get().strip()
            domain = email.split("@")[-1].lower() if "@" in email else ""
            prov_map = {
                "gmail.com":"Gmail","googlemail.com":"Gmail",
                "outlook.com":"Outlook","hotmail.com":"Outlook","live.com":"Outlook",
                "yahoo.com":"Yahoo","ymail.com":"Yahoo",
                "icloud.com":"iCloud","me.com":"iCloud",
            }
            key = prov_map.get(domain, "default")
            instr_var.set(INSTRUCTIONS[key])

        sender_var.trace_add("write", update_instructions)
        update_instructions()

        tk.Label(note_inner, textvariable=instr_var,
                 font=(F, 8), bg=CARD2, fg=MUTED,
                 justify="left", anchor="w").pack(fill="x")

        # ── Status label (in pre-packed outer frame) ──────────────────────────
        status_var = tk.StringVar(value="")
        status_lbl = tk.Label(status_lbl_outer, textvariable=status_var,
                               font=(F, 9), bg=BG, fg=SUCCESS,
                               wraplength=460)
        status_lbl.pack(anchor="w", pady=4)

        PLACEHOLDERS = {
            "sender_email":   "yourname@gmail.com  /  outlook.com  /  yahoo.com  …",
            "receiver_email": "receiver@anyemail.com",
            "sender_password":"Enter app password here",
        }

        def collect():
            for key, var in [("sender_email",   sender_var),
                              ("sender_password",password_var),
                              ("receiver_email", receiver_var)]:
                val = var.get().strip()
                if val == PLACEHOLDERS.get(key, ""): val = cfg.get(key, "")
                cfg[key] = val
            cfg["enabled"] = enabled_var.get()
            so = []
            if crit_var.get(): so.append("critical")
            if warn_var.get(): so.append("warning")
            if info_var.get(): so.append("info")
            cfg["send_on"] = so
            notifier.cfg = cfg
            notifier.save()

        def save_and_close():
            collect()
            status_var.set("✔  Settings saved!")
            status_lbl.configure(fg=SUCCESS)
            win.after(1200, win.destroy)

        def send_test():
            collect()
            if not cfg.get("sender_email") or "@" not in cfg.get("sender_email",""):
                status_var.set("⚠  Please enter a valid sender email address.")
                status_lbl.configure(fg=WARNING); return
            if not cfg.get("sender_password"):
                status_var.set("⚠  Please enter your App Password.")
                status_lbl.configure(fg=WARNING); return
            if not cfg.get("receiver_email") or "@" not in cfg.get("receiver_email",""):
                status_var.set("⚠  Please enter a valid receiver email address.")
                status_lbl.configure(fg=WARNING); return
            status_var.set("📤  Sending test email…")
            status_lbl.configure(fg=ACCENT)
            win.update()
            notifier.test_send()
            def check_result():
                st = notifier._last_status
                if st == "ok":
                    status_var.set("✔  Test email sent! Check your inbox (and Spam folder).")
                    status_lbl.configure(fg=SUCCESS)
                elif st == "auth_error":
                    status_var.set("✖  Authentication failed. Check your App Password.")
                    status_lbl.configure(fg=DANGER)
                elif st.startswith("error"):
                    status_var.set(f"✖  {st}")
                    status_lbl.configure(fg=DANGER)
                else:
                    status_var.set("⏳  Still sending… check inbox in a moment.")
                    status_lbl.configure(fg=MUTED)
            win.after(4000, check_result)

        make_action_button(btn_row, "💾  Save & Enable", save_and_close,
                           bg=ACCENT, fg=BG).pack(side="left", padx=(0,8))
        make_action_button(btn_row, "📤  Send Test Email", send_test,
                           bg=BTN_BG, fg=TEXT).pack(side="left", padx=(0,8))
        make_action_button(btn_row, "Cancel", win.destroy,
                           bg=BTN_BG, fg=MUTED).pack(side="left")

    def _show_detail(self, *_):
        sel = self._tv.selection()
        if not sel: return
        vals = self._tv.item(sel[0])["values"]
        if not vals: return

        win = tk.Toplevel(self, bg=BG)
        win.title("Alert Details")
        win.geometry("560x340")
        win.resizable(True, True)

        # Determine color from level column (index 2)
        level_text = str(vals[2]).lower()
        color = DANGER if "critical" in level_text else                 WARNING if "warning" in level_text else ACCENT

        hdr = tk.Frame(win, bg=CARD, pady=12, padx=20); hdr.pack(fill="x")
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x")
        tk.Label(hdr, text=str(vals[4]),
                 font=(F,13,"bold"), bg=CARD, fg=color).pack(anchor="w")
        tk.Label(hdr, text=f"{vals[2]}  ·  {vals[3]}  ·  {vals[1]} at {vals[0]}",
                 font=(F,9), bg=CARD, fg=MUTED).pack(anchor="w")

        body = tk.Frame(win, bg=BG, padx=20, pady=16); body.pack(fill="both", expand=True)
        for label, val in [("Message", vals[5]), ("Detail", vals[6])]:
            row = tk.Frame(body, bg=BG); row.pack(fill="x", pady=4)
            tk.Label(row, text=label+":", width=10, anchor="e",
                     font=(F,9), bg=BG, fg=MUTED).pack(side="left")
            tk.Label(row, text=str(val), anchor="w", wraplength=420,
                     font=(F,10), bg=BG, fg=TEXT).pack(side="left", padx=10)

        tk.Frame(win, bg=BORDER, height=1).pack(fill="x")
        btn_row = tk.Frame(win, bg=CARD, pady=10, padx=20); btn_row.pack(fill="x")
        make_action_button(btn_row, "Close", win.destroy,
                           bg=BTN_BG, fg=TEXT).pack(side="left")

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = ProXDefendApp()
    app.mainloop()
