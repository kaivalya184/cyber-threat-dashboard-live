from flask import Flask, render_template, jsonify
import socket
import subprocess
import platform
import threading
import psutil
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# ── Shared live state ────────────────────────────────────────────
state = {
    "devices": [],
    "logs": [],
    "stats": {},
    "scanning": False,
    "last_scan": None,
}
state_lock = threading.Lock()

# ── Helpers ──────────────────────────────────────────────────────
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
}

RISKY_PORTS = {23: "Telnet (unencrypted)", 21: "FTP (unencrypted)",
               445: "SMB (ransomware risk)", 3389: "RDP (brute-force target)",
               5900: "VNC (remote access)", 25: "SMTP (spam relay)"}


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    wait  = "-w" if platform.system().lower() == "windows" else "-W"
    cmd   = ["ping", param, "1", wait, "500", str(ip)]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        return "Unknown"


def scan_ports(ip):
    open_ports = []
    for port in PORT_SERVICES:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.4)
            if sock.connect_ex((str(ip), port)) == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports


def risk_level(open_ports):
    risky = [p for p in open_ports if p in RISKY_PORTS]
    if len(risky) >= 2:  return "CRITICAL"
    if len(risky) == 1:  return "HIGH"
    if len(open_ports) > 3: return "MEDIUM"
    if open_ports:       return "LOW"
    return "SAFE"


def scan_host(ip):
    if not ping_host(ip):
        return None
    hostname   = get_hostname(ip)
    open_ports = scan_ports(ip)
    services   = [PORT_SERVICES[p] for p in open_ports]
    risks      = [RISKY_PORTS[p]   for p in open_ports if p in RISKY_PORTS]
    level      = risk_level(open_ports)
    return {
        "ip":        str(ip),
        "hostname":  hostname,
        "status":    "Online",
        "ports":     open_ports,
        "services":  services,
        "risks":     risks,
        "risk_level": level,
        "scanned_at": datetime.now().strftime("%H:%M:%S"),
    }


def add_log(event, ip, status):
    with state_lock:
        state["logs"].insert(0, {
            "time":   datetime.now().strftime("%H:%M:%S"),
            "event":  event,
            "ip":     ip,
            "status": status,
        })
        state["logs"] = state["logs"][:50]   # keep last 50


def run_scan():
    with state_lock:
        if state["scanning"]:
            return
        state["scanning"] = True

    local_ip = get_local_ip()
    network  = str(ipaddress.IPv4Network(
        ".".join(local_ip.split(".")[:3]) + ".0/24", strict=False))
    hosts    = list(ipaddress.IPv4Network(network, strict=False).hosts())

    add_log("Network scan started", local_ip, "INFO")
    found = []

    with ThreadPoolExecutor(max_workers=60) as ex:
        futures = {ex.submit(scan_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                # Log risky devices automatically
                if result["risk_level"] in ("CRITICAL", "HIGH"):
                    add_log(
                        f"Risky device — {', '.join(result['risks'])}",
                        result["ip"],
                        result["risk_level"],
                    )
                else:
                    add_log("Device found online", result["ip"], "OK")

    found.sort(key=lambda x: list(map(int, x["ip"].split("."))))

    with state_lock:
        state["devices"]   = found
        state["scanning"]  = False
        state["last_scan"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    add_log(f"Scan complete — {len(found)} devices found", local_ip, "DONE")


def get_system_stats():
    net_io  = psutil.net_io_counters()
    return {
        "cpu":          psutil.cpu_percent(interval=1),
        "ram":          psutil.virtual_memory().percent,
        "bytes_sent":   round(net_io.bytes_sent   / 1_048_576, 2),
        "bytes_recv":   round(net_io.bytes_recv   / 1_048_576, 2),
        "packets_sent": net_io.packets_sent,
        "packets_recv": net_io.packets_recv,
        "local_ip":     get_local_ip(),
        "hostname":     socket.gethostname(),
    }


# ── Background auto-scan every 90 seconds ────────────────────────
def auto_scan_loop():
    while True:
        threading.Thread(target=run_scan, daemon=True).start()
        threading.Event().wait(90)

threading.Thread(target=auto_scan_loop, daemon=True).start()


# ── Routes ────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    with state_lock:
        devices   = list(state["devices"])
        logs      = list(state["logs"])
        scanning  = state["scanning"]
        last_scan = state["last_scan"]

    stats = get_system_stats()

    # Threat summary
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
    for d in devices:
        risk_counts[d["risk_level"]] = risk_counts.get(d["risk_level"], 0) + 1

    return jsonify({
        "scanning":    scanning,
        "last_scan":   last_scan,
        "devices":     devices,
        "logs":        logs[:20],
        "stats":       stats,
        "risk_counts": risk_counts,
        "total_devices": len(devices),
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"message": "Scan triggered"})


if __name__ == "__main__":
    print("\n🛡  Cyber Threat Dashboard — by Kaivalya Ingole")
    print(f"   Your IP : {get_local_ip()}")
    print("   Open    : http://localhost:5000\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
