from scapy.all import sniff, IP, UDP, DNS, DNSQR, conf
from collections import defaultdict, deque
import time
import json
import atexit
from datetime import datetime

# =========================
# CONFIG
# =========================
TIME_WINDOW       = 5
REQUEST_THRESHOLD = 20
ALERT_COOLDOWN    = 20
PRUNE_INTERVAL    = 60
WHITELIST         = {"127.0.0.1"}
LOG_FILE          = "data/dns_logs.jsonl"
IFACE             = None    # None = auto-detect

# =========================
# QTYPE MAP
# =========================
QTYPE_MAP = {
    1:   "A",
    2:   "NS",
    5:   "CNAME",
    15:  "MX",
    16:  "TXT",
    28:  "AAAA",
    33:  "SRV",
    255: "ANY"
}

# =========================
# STORAGE
# =========================
dns_requests = defaultdict(deque)   # {ip: deque[(timestamp, qname, qtype_str)]}
alerted_ips  = {}
last_prune   = time.time()

# =========================
# JSONL LOGGER
# =========================
log_file = open(LOG_FILE, "a")
atexit.register(log_file.close)

def log_event(data):
    log_file.write(json.dumps(data) + "\n")
    log_file.flush()

# =========================
# CLEAN OLD DATA
# =========================
def clean_requests(ip, now):
    window = dns_requests[ip]
    while window and (now - window[0][0]) > TIME_WINDOW:
        window.popleft()

# =========================
# PRUNE STALE IPs
# =========================
def prune_stale(now):
    stale = [ip for ip, dq in dns_requests.items() if not dq]
    for ip in stale:
        del dns_requests[ip]
        alerted_ips.pop(ip, None)

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(ip):
    data = dns_requests[ip]
    if not data:
        return None

    times  = [t  for t,  _, _  in data]
    qnames = [q  for _,  q, _  in data]
    qtypes = [qt for _,  _, qt in data]

    duration     = max(times) - min(times) if len(times) > 1 else 0
    intervals    = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
    avg_interval = sum(intervals) / len(intervals) if intervals else 0

    unique_domains         = len(set(qnames))
    domain_diversity_ratio = unique_domains / len(qnames)

    domain_counts = defaultdict(int)
    for q in qnames:
        domain_counts[q] += 1
    top_domain       = max(domain_counts, key=domain_counts.get)
    top_domain_ratio = domain_counts[top_domain] / len(qnames)

    type_counts   = defaultdict(int)
    for qt in qtypes:
        type_counts[qt] += 1
    unique_qtypes = len(set(qtypes))

    avg_qname_len = sum(len(q) for q in qnames) / len(qnames)

    return {
        "total_requests"        : len(data),
        "duration"              : round(duration, 3),
        "pps"                   : round(len(data) / max(duration, 1), 3),
        "avg_interval"          : round(avg_interval, 4),
        "unique_domains"        : unique_domains,
        "domain_diversity_ratio": round(domain_diversity_ratio, 3),
        "top_domain"            : top_domain,
        "top_domain_ratio"      : round(top_domain_ratio, 3),
        "unique_qtypes"         : unique_qtypes,
        "type_counts"           : dict(type_counts),
        "avg_qname_len"         : round(avg_qname_len, 2),
    }

# =========================
# SEVERITY
# =========================
def compute_severity(features):
    total = features["total_requests"]
    pps   = features["pps"]
    if total > 100 or pps > 30: return "CRITICAL"
    elif total > 50 or pps > 15: return "HIGH"
    elif total > 30 or pps > 8:  return "MEDIUM"
    else:                         return "LOW"

# =========================
# DETECTION
# =========================
def detect(packet):
    global last_prune

    if not packet.haslayer(IP) or not packet.haslayer(UDP):
        return
    if not packet.haslayer(DNS):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    now    = time.time()

    if ip_src in WHITELIST:
        return

    if packet[DNS].qr != 0:
        return

    if packet.haslayer(DNSQR):
        qname     = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        qtype_str = QTYPE_MAP.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))
    else:
        qname     = "unknown"
        qtype_str = "unknown"

    dns_requests[ip_src].append((now, qname, qtype_str))
    clean_requests(ip_src, now)

    if now - last_prune > PRUNE_INTERVAL:
        prune_stale(now)
        last_prune = now

    features = extract_features(ip_src)
    if not features:
        return

    # =========================
    # LOG EVERY PACKET
    # =========================
    log_event({
        "timestamp" : str(datetime.now()),
        "source_ip" : ip_src,
        "target_ip" : ip_dst,
        "qname"     : qname,
        "qtype"     : qtype_str,
        "label"     : 0,    # default normal — attacker sets to 1
        **features
    })

    # Anti-spam
    last_alert = alerted_ips.get(ip_src, 0)
    if now - last_alert < ALERT_COOLDOWN:
        return

    # =========================
    # DETECTION LOGIC
    # =========================
    alert_type = None

    if features["avg_qname_len"] > 50:
        alert_type = "DNS_TUNNEL"
    elif features["total_requests"] >= REQUEST_THRESHOLD:
        alert_type = "DNS_FLOOD"

    if alert_type:
        severity = compute_severity(features)
        alert = {
            "timestamp" : str(datetime.now()),
            "type"      : alert_type,
            "source_ip" : ip_src,
            "target_ip" : ip_dst,
            "severity"  : severity,
            "label"     : 1,
            **features,
        }
        print(f"🚨 ALERT [{severity}] [{alert_type}] {ip_src} → {ip_dst} "
              f"| {features['total_requests']} req "
              f"| top: {features['top_domain']} "
              f"| pps: {features['pps']} "
              f"| avg_len: {features['avg_qname_len']}")
        log_event(alert)
        alerted_ips[ip_src] = now

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 DNS FLOOD/TUNNEL DETECTION RUNNING on [{iface}]...")
    sniff(
        iface=iface,
        filter="udp port 53",
        prn=detect,
        store=0
    )