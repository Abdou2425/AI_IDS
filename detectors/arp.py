import time
import json
import atexit
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, ARP, conf

# ===============================
# CONFIG
# ===============================
RATE_WINDOW     = 10
RATE_THRESHOLD  = 5
ALERT_THRESHOLD = 4
ALERT_COOLDOWN  = 20
PRUNE_INTERVAL  = 60
WHITELIST       = {"127.0.0.1"}
LOG_FILE        = "data/arp_dataset.jsonl"
IFACE           = None    # None = auto-detect

# ===============================
# DATA STRUCTURES
# ===============================
arp_table    = {}
packet_times = defaultdict(deque)
mac_history  = defaultdict(set)
alerted_ips  = {}
last_prune   = time.time()

# ===============================
# JSONL LOGGER
# ===============================
log_file = open(LOG_FILE, "a")
atexit.register(log_file.close)

def log_entry(data):
    log_file.write(json.dumps(data) + "\n")
    log_file.flush()

# ===============================
# CLEAN OLD DATA (popleft O(1))
# ===============================
def clean_old(ip, now):
    dq = packet_times[ip]
    while dq and now - dq[0] > RATE_WINDOW:
        dq.popleft()

# ===============================
# PRUNE STALE IPs
# ===============================
def prune_stale(now):
    stale = [ip for ip, dq in packet_times.items() if not dq]
    for ip in stale:
        del packet_times[ip]
        mac_history.pop(ip, None)
        alerted_ips.pop(ip, None)

# ===============================
# FEATURE EXTRACTION
# ===============================
def extract_features(ip, packet):
    dq = packet_times[ip]
    if not dq:
        return None

    duration = dq[-1] - dq[0]

    return {
        "packet_rate"   : round(len(dq) / max(duration, 1), 3),
        "unique_macs"   : len(mac_history[ip]),
        "mac_changed"   : int(bool(
                            arp_table.get(ip) and
                            arp_table.get(ip) != packet[ARP].hwsrc
                          )),
        "known_mac"     : arp_table.get(ip),
        "is_gratuitous" : int(packet[ARP].psrc == packet[ARP].pdst),
        "hwdst"         : packet[ARP].hwdst,
        "is_broadcast"  : int(packet[ARP].hwdst == "ff:ff:ff:ff:ff:ff"),
    }

# ===============================
# SEVERITY
# ===============================
def compute_severity(score):
    if score >= 9: return "HIGH"
    if score >= 6: return "MEDIUM"
    return "LOW"

# ===============================
# DETECTION ENGINE
# ===============================
def detect_arp(packet):
    global last_prune

    if not (packet.haslayer(ARP) and packet[ARP].op == 2):
        return

    ip  = packet[ARP].psrc
    mac = packet[ARP].hwsrc
    now = time.time()

    if ip in WHITELIST:
        return

    packet_times[ip].append(now)
    mac_history[ip].add(mac)
    clean_old(ip, now)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(now)
        last_prune = now

    features = extract_features(ip, packet)
    if not features:
        return

    mac_changed   = features["mac_changed"]
    known_mac     = features["known_mac"]
    rate          = features["packet_rate"]
    unique_macs   = features["unique_macs"]
    is_gratuitous = features["is_gratuitous"]
    hwdst         = features["hwdst"]
    is_broadcast  = features["is_broadcast"]

    # ===============================
    # SUSPICION SCORING
    # ===============================
    score = 0
    if mac_changed:           score += 3
    if unique_macs > 2:       score += 2
    if rate > RATE_THRESHOLD: score += 1
    if is_gratuitous:         score += 2
    if is_broadcast:          score += 2

    # ===============================
    # LOG EVERY PACKET
    # ===============================
    log_entry({
        "timestamp"    : str(datetime.now()),
        "ip"           : ip,
        "mac"          : mac,
        "known_mac"    : known_mac,
        "mac_changed"  : mac_changed,
        "packet_rate"  : rate,
        "unique_macs"  : unique_macs,
        "is_gratuitous": is_gratuitous,
        "hwdst"        : hwdst,
        "is_broadcast" : is_broadcast,
        "score"        : score,
        "label"        : 0    # default normal — attacker sets to 1
    })

    # ===============================
    # ANTI-SPAM
    # ===============================
    last_alert = alerted_ips.get(ip, 0)
    if now - last_alert < ALERT_COOLDOWN:
        arp_table[ip] = mac
        return

    # ===============================
    # ALERT
    # ===============================
    if score >= ALERT_THRESHOLD:
        severity = compute_severity(score)
        alert = {
            "timestamp"    : str(datetime.now()),
            "type"         : "ARP_SPOOFING",
            "source_ip"    : ip,
            "source_mac"   : mac,
            "known_mac"    : known_mac,
            "hwdst"        : hwdst,
            "is_gratuitous": bool(is_gratuitous),
            "is_broadcast" : bool(is_broadcast),
            "score"        : score,
            "severity"     : severity,
            "label"        : 1
        }
        print(f"🚨 ALERT [ARP_SPOOFING] [{severity}] {ip} | score: {score}")
        log_entry(alert)
        alerted_ips[ip] = now

    arp_table[ip] = mac

# ===============================
# START
# ===============================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 ARP SPOOFING DETECTION RUNNING on [{iface}]...")
    sniff(
        iface=iface,
        filter="arp",
        prn=detect_arp,
        store=0
    )