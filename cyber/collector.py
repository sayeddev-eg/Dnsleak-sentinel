"""
collector.py — ملتقط ومحلل حزم DNS (DNS Packet Collector & Streamer)
فريق السايبر: يحيى وبودا
المهمة:
- التقاط استعلامات DNS الحية (Live Sniffing) أو قراءة ملفات الشبكة (PCAP / PCAPNG)
- استخراج الخصائص الـ 16 المعتمدة بالتعاون مع ai_core
- فحص القائمة البيضاء (whitelist.csv) وتقييم المخاطر عبر risk_engine
- إرسال البيانات لحظياً لخادم الباك إند (FastAPI) لتحديث لوحة التحكم
"""

import sys
import time
import argparse
from pathlib import Path
from typing import Optional, List

CURRENT_DIR = Path(__file__).resolve().parent
BASE_DIR = CURRENT_DIR.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(CURRENT_DIR))

import requests
from ai_core.features import extract_domain_features, QTYPE_MAP
from cyber.risk_engine import RiskEngine

BACKEND_API = "http://127.0.0.1:8000/api/v1/predict/features"

# تهيئة محرك المخاطر المعتمد على القائمة البيضاء
risk_engine = RiskEngine()


def send_packet_to_backend(qname: str, src_ip: str, qtype_str: str = "A", packet_sz: int = 128) -> bool:
    """استخراج الخصائص وإرسالها للباك إند"""
    clean_qname = qname.rstrip(".")
    if not clean_qname:
        return False

    # استخراج الـ 16 Feature مطابقة للموديل والسكيما
    features = extract_domain_features(clean_qname, qtype_str, packet_sz)

    payload = {
        "src_ip": src_ip,
        "domain": clean_qname,
        "features": features
    }

    try:
        resp = requests.post(BACKEND_API, json=payload, timeout=4)
        if resp.status_code == 200:
            data = resp.json().get("prediction", {})
            level = data.get("level", "NORMAL")
            prob = data.get("attack_probability", 0) * 100
            reasons = ", ".join(data.get("reasons", []))

            prefix = "[!]" if level == "CRITICAL" else ("[*]" if level == "SUSPICIOUS" else "[+]")
            print(f"{prefix} {src_ip:<15} -> {clean_qname[:35]:<35} | {level:<10} ({prob:5.1f}%) {reasons}")
            return True
    except requests.exceptions.RequestException as e:
        print(f"[!] Cannot connect to backend ({BACKEND_API}): {e}")
        return False
    return False


def stream_pcap(pcap_path: Path, delay: float = 0.05, max_packets: Optional[int] = None):
    """قراءة وبث الحزم من ملف PCAP / PCAPNG"""
    if not pcap_path.exists():
        print(f"[!] PCAP file not found: {pcap_path}")
        return

    try:
        from scapy.all import PcapReader, DNS, DNSQR, IP, IPv6
    except ImportError:
        print("[!] Scapy is required for PCAP streaming. Install via: pip install scapy")
        return

    print(f"\n[*] Streaming packets from {pcap_path.name} to {BACKEND_API}...")
    count = 0

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qname_bytes = pkt[DNSQR].qname
                if not qname_bytes:
                    continue
                qname = qname_bytes.decode(errors="ignore").rstrip(".")
                if not qname:
                    continue

                src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "192.168.1.105")
                qtype_code = pkt[DNSQR].qtype
                qtype_str = QTYPE_MAP.get(qtype_code, "A")
                pkt_sz = len(pkt)

                success = send_packet_to_backend(qname, src_ip, qtype_str, pkt_sz)
                if success:
                    count += 1
                    if delay > 0:
                        time.sleep(delay)

                if max_packets and count >= max_packets:
                    break

    print(f"[OK] Finished streaming {count} packets from {pcap_path.name}.")


def start_live_sniffing(interface: Optional[str] = None):
    """تشغيل الالتقاط الحي لحزم الـ DNS على المنفذ 53"""
    try:
        from scapy.all import sniff, DNS, DNSQR, IP, IPv6
    except ImportError:
        print("[!] Scapy is required for live sniffing. Run: pip install scapy")
        return

    print("=" * 65)
    print("[*] Starting Live DNS Sniffer (UDP Port 53)...")
    print("[*] Note: Requires administrative privileges and Npcap on Windows.")
    print("=" * 65)

    def packet_callback(pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname_bytes = pkt[DNSQR].qname
            if not qname_bytes:
                return
            qname = qname_bytes.decode(errors="ignore").rstrip(".")
            if not qname:
                return

            src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "192.168.1.50")
            qtype_str = QTYPE_MAP.get(pkt[DNSQR].qtype, "A")
            send_packet_to_backend(qname, src_ip, qtype_str, len(pkt))

    try:
        sniff(filter="udp port 53", prn=packet_callback, store=False, iface=interface)
    except Exception as e:
        print(f"[!] Live sniffing error (Check Admin/Npcap): {e}")


def main():
    parser = argparse.ArgumentParser(description="DNSLeak Sentinel — Packet Collector")
    parser.add_argument("--file", type=str, help="Path to PCAP file to stream")
    parser.add_argument("--normal", action="store_true", help="Stream dns_normal_trafic.pcapng")
    parser.add_argument("--dataset", action="store_true", help="Stream traffic_dataset.pcap")
    parser.add_argument("--live", action="store_true", help="Start live network sniffing on port 53")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between packets (seconds)")
    args = parser.parse_args()

    if args.live:
        start_live_sniffing()
    elif args.file:
        stream_pcap(Path(args.file), delay=args.delay)
    elif args.dataset:
        pcap_path = CURRENT_DIR / "traffic_dataset.pcap"
        stream_pcap(pcap_path, delay=args.delay)
    elif args.normal:
        pcap_path = CURRENT_DIR / "dns_normal_trafic.pcapng"
        stream_pcap(pcap_path, delay=args.delay)
    else:
        # الوضع التلقائي: فحص الملفات المتاحة
        normal_pcap = CURRENT_DIR / "dns_normal_trafic.pcapng"
        dataset_pcap = CURRENT_DIR / "traffic_dataset.pcap"
        target = dataset_pcap if dataset_pcap.exists() else normal_pcap
        if target.exists():
            stream_pcap(target, delay=args.delay, max_packets=100)
        else:
            print("[!] No default PCAP file found. Generate one with: python generate.py")


if __name__ == "__main__":
    main()