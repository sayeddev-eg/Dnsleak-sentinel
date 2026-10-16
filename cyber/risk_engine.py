"""
risk_engine.py — محرك تقييم المخاطر والقائمة البيضاء (Risk Engine & Whitelist Integration)
فريق السايبر: عمران ويحيى وبودا
المهمة:
- فحص استعلامات DNS ومقارنتها بالقائمة البيضاء (whitelist.csv) لتقليل الإنذارات الكاذبة (False Positives)
- تقييم شانون إنتروبي (Shannon Entropy) وحجم وطول النطاقات
- الكشف عن أنماط تسريب البيانات وأنفاق DNS وفقاً لـ MITRE ATT&CK (T1071.004, T1048.003)
- توليد تقرير أمني (suspicious_report.csv) لحركة الشبكة
"""

import math
import csv
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

CURRENT_DIR = Path(__file__).resolve().parent
DEFAULT_WHITELIST_PATH = CURRENT_DIR / "whitelist.csv"
DEFAULT_PCAP_PATH = CURRENT_DIR / "dns_normal_trafic.pcapng"


def calculate_entropy(text: str) -> float:
    """حساب شانون إنتروبي لقياس العشوائية والتشفير (Base32/Base64/Hex) في النطاق"""
    if not text:
        return 0.0
    text_len = len(text)
    frequencies = {c: text.count(c) for c in set(text)}
    return round(-sum((cnt / text_len) * math.log2(cnt / text_len) for cnt in frequencies.values()), 4)


class RiskEngine:
    """محرك المخاطر الأمني لفحص حركة الـ DNS وتقليل الإنذارات الكاذبة"""

    def __init__(self, whitelist_path: Optional[Path] = None):
        self.whitelist_path = Path(whitelist_path) if whitelist_path else DEFAULT_WHITELIST_PATH
        self.whitelist_domains: set = set()
        self.whitelist_roots: set = set()
        self.load_whitelist()

    def load_whitelist(self):
        """تحميل القائمة البيضاء من ملف CSV"""
        if not self.whitelist_path.exists():
            print(f"[!] Whitelist file not found at: {self.whitelist_path}")
            return

        try:
            with open(self.whitelist_path, mode="r", encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row or row[0].startswith("#"):
                        continue
                    domain = row[-1].strip().lower()
                    if "." in domain and domain != "domain":
                        self.whitelist_domains.add(domain)
                        parts = domain.split(".")
                        if len(parts) >= 2:
                            self.whitelist_roots.add(".".join(parts[-2:]))
            print(f"[+] RiskEngine: Loaded {len(self.whitelist_domains)} trusted domains from {self.whitelist_path.name}")
        except Exception as e:
            print(f"[!] Error loading whitelist: {e}")

    def is_whitelisted(self, domain: str) -> bool:
        """التحقق مما إذا كان النطاق أو نطاقه الرئيسي ضمن القائمة البيضاء الموثوقة"""
        if not domain:
            return False
        d = domain.lower().strip(".")
        if d in self.whitelist_domains:
            return True
        parts = d.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
            if root in self.whitelist_roots or root in self.whitelist_domains:
                return True
        return False

    def assess_domain(
        self,
        domain: str,
        qtype: str = "A",
        packet_size: int = 128,
        features: Optional[Dict[str, Any]] = None,
        src_ip: str = "192.168.1.100"
    ) -> Dict[str, Any]:
        """
        تقييم أمني شامل للنطاق يدمج القائمة البيضاء مع تحليل الخصائص الرياضية
        """
        clean_domain = domain.lower().strip(".")
        whitelisted = self.is_whitelisted(clean_domain)

        # إذا كان في القائمة البيضاء: اعتباره آمناً مباشرة لتقليل الـ False Positives
        if whitelisted:
            return {
                "domain": clean_domain,
                "src_ip": src_ip,
                "qtype": qtype,
                "is_whitelisted": True,
                "attack_probability": 0.015,
                "risk_score": 2,
                "level": "NORMAL",
                "classification": "benign",
                "reasons": ["Trusted Whitelisted Domain"]
            }

        # حساب الخصائص الأساسية
        entropy = calculate_entropy(clean_domain)
        length = len(clean_domain)
        parts = clean_domain.split(".")
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
        sub_entropy = calculate_entropy(subdomain) if subdomain else 0.0
        hex_chars = set("0123456789abcdefABCDEF")
        hex_ratio = sum(c in hex_chars for c in clean_domain) / length if length > 0 else 0.0
        digit_ratio = sum(c.isdigit() for c in clean_domain) / length if length > 0 else 0.0

        # مؤشرات الخطورة التراكمية
        risk_score = 0
        reasons = []

        # 1. طول النطاق وطول الـ Subdomain
        if length > 50:
            risk_score += 35
            reasons.append("Extreme Domain Length (>50 chars)")
        elif length > 35:
            risk_score += 20
            reasons.append("Unusually Long Domain (>35 chars)")

        if len(subdomain) > 25:
            risk_score += 25
            reasons.append("Long Subdomain Payload (Data Chunks)")

        # 2. العشوائية والتشفير (Entropy)
        if sub_entropy > 4.0 or entropy > 4.2:
            risk_score += 35
            reasons.append("High Shannon Entropy (Likely Base32/Base64/Encrypted)")
        elif sub_entropy > 3.4 or entropy > 3.6:
            risk_score += 20
            reasons.append("Elevated Entropy (Random Character Distribution)")

        # 3. نسبة الأرقام والرموز والترميز الست عشري (Hex/Base)
        if hex_ratio > 0.65 and length > 20:
            risk_score += 25
            reasons.append("High Hexadecimal Character Ratio")

        if digit_ratio > 0.25:
            risk_score += 15
            reasons.append("High Digit Concentration")

        # 4. نوع الاستعلام (TXT, NULL, CNAME تزيد الشبهة في تسريب البيانات)
        if qtype.upper() in ["TXT", "NULL"]:
            risk_score += 15
            reasons.append(f"Suspicious DNS Record Type for Exfiltration ({qtype.upper()})")

        # 5. كلمات دلالية مريبة
        suspicious_keywords = ["tunnel", "exfil", "leak", "c2", "payload", "darknet", "bypass"]
        if any(kw in clean_domain for kw in suspicious_keywords):
            risk_score += 30
            reasons.append("Suspicious DNS Tunneling Keyword Detected")

        # تحويل الـ Risk Score (0-100) لاحتمالية (0.0-1.0)
        risk_score = min(100, risk_score)
        prob = round(risk_score / 100.0, 4)

        # تحديد مستوى الخطر وفقاً لوثيقة المشروع (صفحة 10)
        if prob >= 0.90:
            level = "CRITICAL"
            classification = "suspicious"
        elif prob >= 0.60:
            level = "SUSPICIOUS"
            classification = "suspicious"
        else:
            level = "NORMAL"
            classification = "benign"
            reasons = []

        return {
            "domain": clean_domain,
            "src_ip": src_ip,
            "qtype": qtype,
            "is_whitelisted": False,
            "attack_probability": prob,
            "risk_score": risk_score,
            "level": level,
            "classification": classification,
            "reasons": reasons,
            "mitre_technique": "T1048.003 / T1071.004" if level != "NORMAL" else None
        }

    def analyze_pcap(self, pcap_path: Optional[Path] = None, output_csv: Optional[str] = "suspicious_report.csv") -> List[Dict[str, Any]]:
        """تحليل ملف PCAP ومقارنته مع القائمة البيضاء وحفظ تقرير الشبهات"""
        path = Path(pcap_path) if pcap_path else DEFAULT_PCAP_PATH
        if not path.exists():
            print(f"[!] PCAP file not found: {path}")
            return []

        try:
            from scapy.all import rdpcap, DNS, DNSQR, IP, IPv6
        except ImportError:
            print("[!] Scapy is not installed. Run: pip install scapy")
            return []

        print(f"[*] Analyzing PCAP traffic: {path.name}...")
        packets = rdpcap(str(path))
        suspicious_list = []
        seen_domains = set()

        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname
                if not qname:
                    continue
                domain = qname.decode("utf-8", errors="ignore").rstrip(".")
                if not domain or domain in seen_domains:
                    continue
                seen_domains.add(domain)

                src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else "192.168.1.100")
                result = self.assess_domain(domain, src_ip=src_ip)

                if result["level"] != "NORMAL":
                    suspicious_list.append(result)

        print(f"[+] Analysis complete. Found {len(suspicious_list)} suspicious domains out of {len(seen_domains)} unique domains.")

        if output_csv and suspicious_list:
            out_file = CURRENT_DIR / output_csv
            try:
                with open(out_file, mode="w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=["domain", "src_ip", "level", "risk_score", "attack_probability", "reasons", "mitre_technique"]
                    )
                    writer.writeheader()
                    for item in suspicious_list:
                        row = item.copy()
                        row["reasons"] = " | ".join(row.get("reasons", []))
                        row.pop("is_whitelisted", None)
                        row.pop("qtype", None)
                        row.pop("classification", None)
                        writer.writerow(row)
                print(f"[OK] Suspicious report saved successfully to: {out_file.name}")
            except Exception as e:
                print(f"[!] Error saving CSV report: {e}")

        return suspicious_list


# Singleton instance للاستخدام المباشر
default_risk_engine = RiskEngine()


if __name__ == "__main__":
    print("=" * 65)
    print("DNSLeak Sentinel — Risk Engine & Traffic Analyzer")
    print("=" * 65)
    engine = RiskEngine()
    engine.analyze_pcap()
