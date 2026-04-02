from scapy.all import sniff, conf
from detectors import syn, arp, icmp, dns, bruteforce

# =========================
# IFACE
# =========================
IFACE = None    # None = auto-detect

# =========================
# UNIFIED PACKET ROUTER
# =========================
def route(packet):
    syn.detect(packet)
    arp.detect_arp(packet)
    icmp.detect(packet)
    dns.detect(packet)
    bruteforce.detect(packet)

# =========================
# START
# =========================
if __name__ == "__main__":
    iface = IFACE or conf.iface
    print(f"🚀 AI-IDS MANAGER RUNNING on [{iface}]")
    print("   Detectors: SYN | ARP | ICMP | DNS | BRUTEFORCE")
    sniff(
        iface=iface,
        prn=route,
        store=0
    )
