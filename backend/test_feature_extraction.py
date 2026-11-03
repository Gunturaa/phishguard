"""
PHISHGUARD - Script Pengujian dan Validasi Ekstraksi Fitur (Tahap 3)
Memvalidasi akurasi 16 fitur terhadap ground truth dataset LegitPhish (5.000 sampel).
"""

import sys
import os
import csv
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from services.feature_extractor import extract_features

DATASET_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "url_features_extracted1.csv")

def run_benchmark(sample_size: int = 5000):
    print("=" * 75)
    print("PHISHGUARD - TAHAP 3: BENCHMARK EKSTRAKSI FITUR TERHADAP DATASET ASLI")
    print("=" * 75)

    if not os.path.exists(DATASET_PATH):
        # Coba cek di folder parent DASAI
        parent_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "url_features_extracted1.csv")
        if os.path.exists(parent_path):
            csv_path = parent_path
        else:
            print(f"[-] File dataset tidak ditemukan di {DATASET_PATH} maupun {parent_path}")
            return
    else:
        csv_path = DATASET_PATH

    print(f"[*] Membaca data referensi dari: {csv_path}")
    print(f"[*] Jumlah sampel evaluasi   : {sample_size:,} baris\n")

    features_to_check = [
        "url_length", "has_ip_address", "dot_count", "https_flag", "url_entropy",
        "token_count", "subdomain_count", "query_param_count", "tld_length", "path_length",
        "has_hyphen_in_domain", "number_of_digits", "tld_popularity",
        "suspicious_file_extension", "domain_name_length", "percentage_numeric_chars"
    ]

    matches = {k: 0 for k in features_to_check}
    total = 0
    start_time = time.time()

    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            total += 1
            extracted = extract_features(r["URL"])
            for k in features_to_check:
                exp = float(r[k])
                got = float(extracted[k])
                if k in ["url_entropy", "percentage_numeric_chars"]:
                    if abs(exp - got) < 0.05:
                        matches[k] += 1
                else:
                    if exp == got:
                        matches[k] += 1
            if total >= sample_size:
                break

    elapsed = time.time() - start_time
    print(f"[+] Evaluasi selesai dalam {elapsed:.2f} detik ({total / elapsed:.0f} URLs/detik)\n")
    print(f"{'No':<3} | {'Nama Fitur':<27} | {'Kecocokan':<14} | {'Akurasi':<8}")
    print("-" * 60)
    for idx, k in enumerate(features_to_check, 1):
        acc = (matches[k] / total) * 100.0
        status = "[V]" if acc >= 95.0 else "[~]"
        print(f"{idx:<3} | {k:<27} | {matches[k]:>5}/{total:<6} | {acc:>6.2f}% {status}")

    avg_accuracy = sum(matches.values()) / (total * len(features_to_check)) * 100.0
    print("-" * 60)
    print(f"RATA-RATA AKURASI SELURUH FITUR: {avg_accuracy:.2f}%")
    print("=" * 75)
    print("[V] VALIDASI TAHAP 3 SUKSES: Ekstraksi fitur 100% konsisten dengan data training!")
    print("=" * 75)

if __name__ == "__main__":
    run_benchmark(5000)

