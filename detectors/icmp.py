from scapy.all import sniff, IP, ICMP, conf
from collections import defaultdict, deque
import time
import json
import atexit
from datetime import datetime

# =========================
# CONFIG
# =========================
TIME_WINDOW     = 5
ICMP_FLOOD_RATE = 20
ALERT_COOLDOWN  = 20
PRUNE_INTERVAL  = 60
WHITELIST       = {"127.0.0.1"}
LOG_FILE        = "data/icmp_dataset.jsonl"
IFACE           = None    # None = auto-detect

# =========================
# STORAGE
# =========================
traffic_data = defaultdict(deque)   # ip → [(timestamp, size)]
alerted_ips  = {}
last_prune   = time.time()

# =========================
# JSONL LOGGER
# =========================
log_file = open(LOG_FILE, "a")
atexit.register(log_file.close)

def log_entry(data):
    log_file.write(json.dumps(data) + "\n")
    log_file.flush()

# =========================
# CLEAN OLD DATA (popleft O(1))
# =========================
def clean_old(ip, now):
    dq = traffic_data[ip]
    while dq and now - dq[0][0] > TIME_WINDOW:
        dq.popleft()

# =========================
# PRUNE STALE IPs
# =========================
def prune_stale(now):
    stale = [ip for ip, dq in traffic_data.items() if not dq]
    for ip in stale:
        del traffic_data[ip]
        alerted_ips.pop(ip, None)

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(ip):
    data = traffic_data[ip]
    if not data:
        return None

    times = [ts for ts, _  in data]
    sizes = [sz for _,  sz in data]

    duration = max(times) - min(times) if len(times) > 1 else 0

    return {
        "total_packets"  : len(data),
        "duration"       : round(duration, 3),
        "pps"            : round(len(data) / max(duration, 1), 3),
        "avg_packet_size": round(sum(sizes) / len(sizes), 2),
        "max_packet_size": max(sizes)
    }

# =========================
# SEVERITY
# =========================
def compute_severity(pps):
    if pps > ICMP_FLOOD_RATE * 4: return "CRITICAL"
    if pps > ICMP_FLOOD_RATE * 2: return "HIGH"
    if pps > ICMP_FLOOD_RATE:     return "MEDIUM"
    return "LOW"

# =========================
# DETECTION ENGINE
# =========================
def detect(packet):
    global last_prune

    if not packet.haslayer(IP) or not packet.haslayer(ICMP):
        return

    if packet[ICMP].type != 8:
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    now    = time.time()

    if ip_src in WHITELIST:
        return

    traffic_data[ip_src].append((now, len(packet)))
    clean_old(ip_src, now)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(now)
        last_prune = now

    features = extract_features(ip_src)
    if not features:
        return

    total_packets   = features["total_packets"]
    duration        = features["duration"]
    pps             = features["pps"]
    avg_packet_size = features["avg_packet_size"]
    max_packet_size = features["max_packet_size"]

    # =========================
    # LOG EVERY PACKET
    # =========================
    log_entry({
        "timestamp"      : str(datetime.now()),
        "source_ip"      : ip_src,
        "target_ip"      : ip_dst,
        "total_packets"  : total_packets,
        "duration"       : duration,
        "pps"            : pps,
        "avg_packet_size": avg_packet_size,
        "max_packet_size": max_packet_size,
        "label"          : 0    # default normal — attacker sets to 1
    })

    # =========================
    # ANTI-SPAM
    # =========================
    last_alert = alerted_ips.get(ip_src, 0)
    if now - last_alert < ALERT_COOLDOWN:
        return

    # =========================
    # ICMP FLOOD DETECTION
    # =========================
    if pps > ICMP_FLOOD_RATE:
        severity = compute_severity(pps)
        alert = {
            "timestamp"      : str(datetime.now()),
            "type"           : "ICMP_FLOOD",
            "source_ip"      : ip_src,
            "target_ip"      : ip_dst,
            "pps"            : pps,
            "total_packets"  : total_packets,
            "duration"       : duration,
            "avg_packet_size": avg_packet_size,
            "max_packet_size": max_packet_size,
            "severity"       : severity,
            "label"          : 1
        }
        print(f"🚨 ALERT [ICMP_FLOOD] [{severity}] {ip_src} → {ip_dst} | pps: {pps:.2f}")
        log_entry(alert)
        alerted_ips[ip_src] = now
        traffic_data[ip_src].clear()

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 ICMP FLOOD DETECTION RUNNING on [{iface}]...")
    sniff(
        iface=iface,
        filter="icmp",
        prn=detect,
        store=0
    )
