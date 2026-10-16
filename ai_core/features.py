"""
features.py — استخراج الخصائص (Feature Engineering) لحركة استعلامات DNS
فريق الذكاء الاصطناعي: روان ومنة
المهمة:
- تحويل استعلام DNS إلى الـ 16 خاصية رقمية وتصنيفية المعتمدة لتدريب وتقييم الموديل (XGBoost)
- حساب شانون إنتروبي (Shannon Entropy) لقياس العشوائية والتشفير
- حساب نسب الأرقام، المحارف الست عشرية، الرموز الخاصة، وتكرار الأرقام
- التوافق التام مع سكيما النموذج (dnsleak_feature_schema.json)
"""

import math
import re
from typing import Any, Dict, Tuple, Optional

try:
    import pandas as pd
except ImportError:
    pd = None

# خريطة أكواد استعلامات الـ DNS الشائعة
QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY"
}


def calculate_entropy(text: str) -> float:
    """حساب شانون إنتروبي (Shannon Entropy) لقياس عشوائية وتشفير المحارف في النطاق"""
    if not text:
        return 0.0
    text_len = len(text)
    frequencies = {c: text.count(c) for c in set(text)}
    return round(-sum((cnt / text_len) * math.log2(cnt / text_len) for cnt in frequencies.values()), 4)


def split_domain(qname: str) -> Tuple[str, str]:
    """فصل النطاق الفرعي (Subdomain) عن النطاق الأساسي (Root Domain)"""
    parts = qname.split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return "", qname


def get_max_consecutive_digits(text: str) -> int:
    """حساب أطول سلسلة متتالية من الأرقام في النطاق"""
    matches = re.findall(r"\d+", text)
    return max([len(m) for m in matches], default=0)


def extract_domain_features(qname: str, qtype_str: str = "A", packet_sz: int = 128) -> Dict[str, Any]:
    """
    استخراج الـ 16 خاصية المعتمدة في الموديل:
    1. qname_len
    2. subdomain_len
    3. subdomain_entropy
    4. qname_entropy
    5. digit_ratio
    6. packet_size
    7. label_count
    8. subdomain_label_count
    9. max_label_len
    10. avg_label_len
    11. unique_char_ratio
    12. consecutive_digit_count
    13. special_char_ratio
    14. hex_char_ratio
    15. subdomain_len_ratio
    16. qtype
    """
    clean_qname = qname.strip().lower().rstrip(".")
    subdomain, _ = split_domain(clean_qname)
    labels = clean_qname.split(".") if clean_qname else []
    subdomain_labels = subdomain.split(".") if subdomain else []

    qname_len = len(clean_qname)
    subdomain_len = len(subdomain)
    label_lens = [len(lbl) for lbl in labels]
    max_lbl_len = max(label_lens) if label_lens else 0
    avg_lbl_len = round(sum(label_lens) / len(label_lens), 4) if label_lens else 0.0

    digit_count = sum(c.isdigit() for c in clean_qname)
    digit_ratio = round(digit_count / qname_len, 4) if qname_len > 0 else 0.0

    hex_chars = set("0123456789abcdefABCDEF")
    hex_count = sum(c in hex_chars for c in clean_qname)
    hex_char_ratio = round(hex_count / qname_len, 4) if qname_len > 0 else 0.0

    unique_char_ratio = round(len(set(clean_qname)) / qname_len, 4) if qname_len > 0 else 0.0
    special_count = sum(not c.isalnum() and c != "." for c in clean_qname)
    special_char_ratio = round(special_count / qname_len, 4) if qname_len > 0 else 0.0
    subdomain_len_ratio = round(subdomain_len / qname_len, 4) if qname_len > 0 else 0.0
    consecutive_digits = get_max_consecutive_digits(clean_qname)

    return {
        "qname_len": qname_len,
        "subdomain_len": subdomain_len,
        "subdomain_entropy": calculate_entropy(subdomain),
        "qname_entropy": calculate_entropy(clean_qname),
        "digit_ratio": digit_ratio,
        "packet_size": packet_sz,
        "label_count": len(labels),
        "subdomain_label_count": len(subdomain_labels),
        "max_label_len": max_lbl_len,
        "avg_label_len": avg_lbl_len,
        "unique_char_ratio": unique_char_ratio,
        "consecutive_digit_count": consecutive_digits,
        "special_char_ratio": special_char_ratio,
        "hex_char_ratio": hex_char_ratio,
        "subdomain_len_ratio": subdomain_len_ratio,
        "qtype": qtype_str
    }


def extract_features(raw_data: Any) -> Any:
    """
    دالة مرنة تقبل نص اسم النطاق أو قاموساً وترجع DataFrame بالخصائص
    """
    domain = ""
    qtype = "A"
    packet_sz = 128

    if isinstance(raw_data, str):
        domain = raw_data
    elif isinstance(raw_data, dict):
        domain = str(raw_data.get("domain", raw_data.get("qname", "")))
        qtype = str(raw_data.get("qtype", "A"))
        packet_sz = int(raw_data.get("packet_size", 128))
    else:
        domain = str(raw_data)

    feat_dict = extract_domain_features(domain, qtype, packet_sz)

    if pd is not None:
        return pd.DataFrame([feat_dict])
    return feat_dict
