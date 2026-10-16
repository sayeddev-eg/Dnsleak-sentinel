"""
simulator.py — محاكي هجمات تسريب وحقن DNS للعرض الحي (Live Attack Simulator)
فريق السايبر: بودا ويحيى
المهمة:
- محاكاة سيناريوهات حقيقية لتسريب البيانات المشفرة (Base32/Base64 Exfiltration) عبر استعلامات DNS
- اختبار قدرة النظام على كشف تقنيات التهرب (Low-and-Slow Evasion)
- توليد حركة استعلامات طبيعية (Hard Negatives / CDNs / Search Engines) للتأكد من عدم وجود إنذارات خاطئة
- إرسال الاستعلامات مباشرة للباك إند لعرض النتائج الحية على الداشبورد
"""

import base64
import json
import random
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Any, Optional

BACKEND_URL = "http://127.0.0.1:8000/api/v1/predict/features"

# بيانات ومفاتيح حساسة افتراضية لمحاكاة تسريب البيانات
SAMPLE_STOLEN_DATA = [
    "admin:Password123!_API_KEY_sec_994827104928174_session_token",
    "credit_card:4111222233334444:exp:12/28:cvv:981:user:john_doe",
    "DATABASE_URL=postgresql://root:SuperSecret2026@internal-db.corp:5432/finance",
    "BEGIN RSA PRIVATE KEY-----MIIEpAIBAAKCAQEA0m5kX4v...-----END RSA PRIVATE KEY",
    "user_id:7741:auth_cookie:sess_ab820dfa77320491bce99a8b172a8c3d901"
]

SAMPLE_ATTACKER_DOMAINS = [
    "c2-relay.shadow-net.cc",
    "exfil-tunnel.darkops-dns.xyz",
    "payload-receiver.attacker-infra.org",
    "ns1.leak-channel.top",
    "dns-stealer.co.vu"
]

SAMPLE_NORMAL_DOMAINS = [
    "www.google.com",
    "update.googleapis.com",
    "clients2.google.com",
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


def send_to_backend(domain: str, src_ip: str, qtype: str = "A", packet_sz: int = 128) -> Optional[Dict[str, Any]]:
    """استخراج الخصائص وإرسال الاستعلام إلى خادم التحليل"""
    try:
        from ai_core.features import extract_domain_features
        features = extract_domain_features(domain, qtype, packet_sz)
    except Exception:
        # حساب تقريبي في حال تعذر الاستيراد
        features = {
            "qname_len": len(domain),
            "subdomain_len": len(domain.split(".")[0]) if "." in domain else 0,
            "subdomain_entropy": 3.8,
            "qname_entropy": 3.5,
            "digit_ratio": 0.1,
            "packet_size": packet_sz,
            "label_count": len(domain.split(".")),
            "subdomain_label_count": 1,
            "max_label_len": 20,
            "avg_label_len": 8.0,
            "unique_char_ratio": 0.6,
            "consecutive_digit_count": 2,
            "special_char_ratio": 0.0,
            "hex_char_ratio": 0.4,
            "subdomain_len_ratio": 0.5,
            "qtype": qtype
        }

    payload = {
        "src_ip": src_ip,
        "domain": domain,
        "features": features
    }

    req = urllib.request.Request(
        BACKEND_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            pred = data.get("prediction", {})
            level = pred.get("level", "UNKNOWN")
            prob = pred.get("attack_probability", 0) * 100
            reasons = ", ".join(pred.get("reasons", []))
            
            tag = f"[{level}]"
            color_prefix = "[!]" if level == "CRITICAL" else ("[*]" if level == "SUSPICIOUS" else "[+]")
            print(f"{color_prefix} {src_ip:<15} -> {domain[:40]:<40} | {tag:<12} ({prob:5.1f}%) {reasons}")
            return data
    except urllib.error.URLError as e:
        print(f"[!] Backend unreachable at {BACKEND_URL}: {e.reason}")
        return None


def generate_exfiltration_chunks(text: str, chunk_size: int = 32, use_base32: bool = True) -> List[str]:
    """تشفير النصوص وتقسيمها إلى Chunks كما تفعل أدوات تسريب DNS الحقيقية (dnscat2, iodine)"""
    data_bytes = text.encode("utf-8")
    if use_base32:
        encoded = base64.b32encode(data_bytes).decode("ascii").lower().rstrip("=")
    else:
        encoded = base64.b64encode(data_bytes).decode("ascii").lower().rstrip("=").replace("+", "-").replace("/", "_")

    return [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]


def simulate_attack_exfiltration(src_ip: str = "192.168.1.188", chunk_delay: float = 0.3):
    """سيناريو 1: هجوم تسريب بيانات سريع وكثيف (Full Exfiltration Attack)"""
    secret = random.choice(SAMPLE_STOLEN_DATA)
    attacker_c2 = random.choice(SAMPLE_ATTACKER_DOMAINS)
    chunks = generate_exfiltration_chunks(secret, chunk_size=36, use_base32=True)
    session_id = f"sess{random.randint(100, 999)}"

    print(f"\n[>>>] STARTING ATTACK SIMULATION: Exfiltrating {len(chunks)} chunks via DNS to {attacker_c2}")
    for idx, chunk in enumerate(chunks):
        # بناء اسم النطاق النمطي للهجوم: chunk.sequence.session.attacker.com
        query_domain = f"{chunk}.{idx:02d}.{session_id}.{attacker_c2}"
        send_to_backend(query_domain, src_ip, qtype="TXT", packet_sz=random.randint(140, 260))
        time.sleep(chunk_delay)
    print("[OK] Attack simulation complete.\n")


def simulate_low_and_slow(src_ip: str = "192.168.1.199", count: int = 4, delay: float = 1.0):
    """سيناريو 2: هجوم التهرب البطيء (Low-and-Slow Evasion) لتخطي أنظمة كشف التردد"""
    attacker_c2 = random.choice(SAMPLE_ATTACKER_DOMAINS)
    print(f"\n[>>>] STARTING LOW-AND-SLOW SIMULATION: Stealth exfiltration to {attacker_c2}")
    for i in range(count):
        hex_data = f"{random.getrandbits(64):016x}{random.getrandbits(32):08x}"
        query_domain = f"{hex_data}.part{i}.{attacker_c2}"
        send_to_backend(query_domain, src_ip, qtype="A", packet_sz=random.randint(90, 140))
        time.sleep(delay)
    print("[OK] Low-and-slow simulation complete.\n")


def simulate_benign_traffic(count: int = 5, delay: float = 0.2):
    """سيناريو 3: حركة تصفح طبيعية واختبار القائمة البيضاء (Hard Negatives)"""
    print(f"\n[>>>] SIMULATING BENIGN WEB TRAFFIC: Sending legitimate queries...")
    for _ in range(count):
        dom = random.choice(SAMPLE_NORMAL_DOMAINS)
        ip = f"192.168.1.{random.randint(10, 80)}"
        send_to_backend(dom, ip, qtype=random.choice(["A", "AAAA"]), packet_sz=random.randint(55, 95))
        time.sleep(delay)
    print("[OK] Benign simulation complete.\n")


def run_live_loop(interval: float = 2.0):
    """حلقة المحاكاة الحية للعرض التوضيحي (Live Demo Loop)"""
    print("=" * 70)
    print("DNSLeak Sentinel — Cyber Attack & Traffic Simulator")
    print(f"Target Backend: {BACKEND_URL}")
    print("Simulating realistic mix: 70% Normal Traffic | 30% Leak Attacks")
    print("Press Ctrl+C to stop.")
    print("=" * 70)

    try:
        while True:
            if random.random() < 0.35:
                # هجوم تسريب
                if random.random() < 0.5:
                    simulate_attack_exfiltration(src_ip="192.168.1.215", chunk_delay=0.2)
                else:
                    simulate_low_and_slow(src_ip="192.168.1.220", count=3, delay=0.5)
            else:
                # طلبات طبيعية
                simulate_benign_traffic(count=random.randint(2, 4), delay=0.1)

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Simulator terminated by user.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--attack":
        simulate_attack_exfiltration()
    elif len(sys.argv) > 1 and sys.argv[1] == "--normal":
        simulate_benign_traffic(count=5)
    else:
        run_live_loop(interval=2.0)
