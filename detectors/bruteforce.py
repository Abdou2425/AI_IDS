from scapy.all import sniff, IP, TCP, conf
from collections import defaultdict, deque
import time
import json
import atexit
from datetime import datetime

# =========================
# CONFIG
# =========================
TIME_WINDOW       = 10
ATTEMPT_THRESHOLD = 15
ALERT_COOLDOWN    = 20
PRUNE_INTERVAL    = 60
TARGET_PORTS      = {22, 21, 23}
WHITELIST         = {"127.0.0.1"}
LOG_FILE          = "data/bruteforce_logs.jsonl"
IFACE             = None

# =========================
# STORAGE
# =========================
attempts    = defaultdict(deque)
alerted_ips = {}
last_prune  = time.time()

# =========================
# LOGGER
# =========================
log_file = open(LOG_FILE, "a")
atexit.register(log_file.close)

def log_event(data):
    log_file.write(json.dumps(data) + "\n")
    log_file.flush()

# =========================
# PRIVATE IP CHECK          ← fix 1
# =========================
def is_private(ip):
    if ip.startswith(("192.168.", "10.")):
        return True
    parts = ip.split(".")
    if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
        return True
    return False

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(ip):
    data = attempts[ip]
    if not data:
        return None

    ports = [p for p, _, _ in data]
    times = [t for _, t, _ in data]
    flags = [f for _, _, f in data]

    duration     = max(times) - min(times) if len(times) > 1 else 0
    intervals    = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
    avg_interval = sum(intervals) / len(intervals) if intervals else 0

    port_counts      = defaultdict(int)
    for p in ports:
        port_counts[p] += 1
    max_port         = max(port_counts.values())
    port_focus_ratio = max_port / len(ports)

    syn_count = sum(1 for f in flags if "S" in f and "A" not in f)
    syn_ratio = syn_count / len(flags)

    return {
        "total_attempts"  : len(data),
        "unique_ports"    : len(set(ports)),
        "duration"        : round(duration, 3),
        "pps"             : round(len(data) / max(duration, 1), 3),
        "avg_interval"    : round(avg_interval, 4),
        "port_focus_ratio": round(port_focus_ratio, 3),
        "syn_ratio"       : round(syn_ratio, 3),
        "port_counts"     : dict(port_counts)
    }

# =========================
# CLEAN OLD DATA
# =========================
def clean_attempts(ip, now):
    window = attempts[ip]
    while window and (now - window[0][1]) > TIME_WINDOW:
        window.popleft()

# =========================
# PRUNE STALE IPs
# =========================
def prune_stale(now):
    stale = [ip for ip, dq in attempts.items() if not dq]
    for ip in stale:
        del attempts[ip]
        alerted_ips.pop(ip, None)

# =========================
# SEVERITY
# =========================
def compute_severity(total_attempts):
    if total_attempts > 100: return "CRITICAL"
    if total_attempts > 40:  return "HIGH"
    if total_attempts > 20:  return "MEDIUM"
    return "LOW"

# =========================
# DETECTION
# =========================
def detect(packet):
    global last_prune

    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dport  = packet[TCP].dport
    flags  = str(packet[TCP].flags)
    now    = time.time()

    if src_ip in WHITELIST:
        return
    if src_ip == dst_ip:
        return
    if not is_private(dst_ip):          # fix 1
        return
    if dport not in TARGET_PORTS:
        return

    attempts[src_ip].append((dport, now, flags))
    clean_attempts(src_ip, now)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(now)
        last_prune = now

    features = extract_features(src_ip)
    if not features:
        return

    total_attempts   = features["total_attempts"]
    unique_ports     = features["unique_ports"]
    port_focus_ratio = features["port_focus_ratio"]

    # =========================
    # LOG EVERY PACKET
    # =========================
    log_event({
        "timestamp" : str(datetime.now()),
        "source_ip" : src_ip,
        "target_ip" : dst_ip,
        "dport"     : dport,
        "flags"     : flags,
        "label"     : 0,                # fix 4
        **features
    })

    # Anti-spam
    last_alert = alerted_ips.get(src_ip, 0)
    if now - last_alert < ALERT_COOLDOWN:
        return

    # =========================
    # DETECTION LOGIC
    # =========================
    alert_type = None

    if (
        total_attempts >= ATTEMPT_THRESHOLD
        and unique_ports <= 2
        and features["syn_ratio"] > 0.6     # kept — strong signal
                                            # duration < 10 removed — fix 2
    ):
        alert_type = "BRUTE_FORCE"

    elif (
        total_attempts >= 20
        and port_focus_ratio < 0.4
                                            # duration < 15 removed — fix 2
    ):
        alert_type = "CREDENTIAL_STUFFING"

    if alert_type:
        severity = compute_severity(total_attempts)
        alert = {
            "timestamp" : str(datetime.now()),
            "type"      : alert_type,
            "source_ip" : src_ip,
            "target_ip" : dst_ip,
            "severity"  : severity,
            "label"     : 1,            # fix 4
            **features
        }
        print(
            f"🚨 ALERT [{severity}] [{alert_type}] "
            f"{src_ip} → {dst_ip} | attempts: {total_attempts} "
            f"| ports: {unique_ports} | focus: {port_focus_ratio}"
        )
        log_event(alert)
        alerted_ips[src_ip] = now

# =========================
# START
# =========================
if __name__ == "__main__":              # fix 3
    port_filter = " or ".join(f"dst port {p}" for p in TARGET_PORTS)
    bpf_filter  = f"tcp and ({port_filter})"
    iface       = IFACE or conf.iface
    print(f"🚀 BRUTE FORCE DETECTOR RUNNING on [{iface}]")
    print(f"   Filter: {bpf_filter}")
    sniff(
        iface=iface,
        filter=bpf_filter,
        prn=detect,
        store=0
    )