"""
PHISHGUARD - Script Pengujian Otomatis Tahap 2
Menguji Backend FastAPI dan Integrasi Machine Learning Random Forest Model.
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from main import app, root, health_check, scan_url, ScanRequest
from fastapi import HTTPException

def run_tests():
    print("=" * 70)
    print("PHISHGUARD - PENGUJIAN TAHAP 2 (FASTAPI & ML RANDOM FOREST INTEGRATION)")
    print("=" * 70)

    # 1. Test Endpoint GET /
    print("\n[1] Menguji Endpoint GET / ...")
    root_data = root()
    assert root_data["status"] == "online"
    print("    [+] Status:", root_data["status"])
    print("    [+] Deskripsi:", root_data["description"])
    print("    [V] Endpoint Root berhasil!")

    # 2. Test Endpoint GET /health
    print("\n[2] Menguji Endpoint GET /health ...")
    health_data = health_check()
    assert health_data["status"] == "healthy"
    assert health_data["ml_model_ready"] is True
    assert health_data["total_features"] == 16
    print("    [+] Service         :", health_data["service"])
    print("    [+] ML Model Status :", "READY (Loaded)" if health_data["ml_model_ready"] else "NOT READY")
    print("    [+] Total Fitur ML  :", health_data["total_features"])
    print("    [V] Health Check berhasil!")

    # 3. Test POST /scan dengan Legitimate URL
    print("\n[3] Menguji Pemindaian URL Legitimate (Aman)...")
    legit_url = "https://stackoverflow.com/questions/tagged/php"
    res_legit = scan_url(ScanRequest(url=legit_url))
    assert res_legit["ok"] is True
    assert res_legit["machine_learning"]["status"] == "LEGITIMATE"
    assert res_legit["final_status"] == "SAFE"
    print(f"    [+] Target URL  : {legit_url}")
    print(f"    [+] Prediksi ML : {res_legit['machine_learning']['status']} (Class {res_legit['machine_learning']['predicted_class']})")
    print(f"    [+] Confidence  : {res_legit['machine_learning']['confidence'] * 100:.1f}%")
    print(f"    [+] Risk Score  : {res_legit['risk_score']} / 100")
    print(f"    [+] Final Status: {res_legit['final_status']}")
    assert res_legit["heuristic_analysis"]["status"] in {"SAFE", "SUSPICIOUS", "PHISHING"}
    assert isinstance(res_legit["heuristic_analysis"]["findings"], list)
    assert res_legit["threat_intelligence"]["provider"] == "Google Web Risk"
    assert res_legit["threat_intelligence"]["status"] in {
        "CLEAN", "THREAT_DETECTED", "UNAVAILABLE", "ERROR"
    }
    assert 0 <= res_legit["risk_score"] <= 100
    assert res_legit["risk_assessment"]["final_status"] == res_legit["final_status"]
    print("    [V] Deteksi Legitimate berhasil!")

    # 4. Test POST /scan dengan Phishing URL
    print("\n[4] Menguji Pemindaian URL Phishing (Berbahaya)...")
    phish_url = "https://keraekken-loagginnusa.godaddysites.com/"
    res_phish = scan_url(ScanRequest(url=phish_url))
    assert res_phish["ok"] is True
    assert res_phish["machine_learning"]["status"] == "PHISHING"
    assert res_phish["final_status"] in {"SUSPICIOUS", "PHISHING"}
    print(f"    [+] Target URL  : {phish_url}")
    print(f"    [+] Prediksi ML : {res_phish['machine_learning']['status']} (Class {res_phish['machine_learning']['predicted_class']})")
    print(f"    [+] Confidence  : {res_phish['machine_learning']['confidence'] * 100:.1f}%")
    print(f"    [+] Probabilitas: Phishing={res_phish['machine_learning']['probabilities']['phishing'] * 100:.1f}%, Legit={res_phish['machine_learning']['probabilities']['legitimate'] * 100:.1f}%")
    print(f"    [+] Risk Score  : {res_phish['risk_score']} / 100")
    print(f"    [+] Final Status: {res_phish['final_status']}")
    assert res_phish["heuristic_analysis"]["status"] in {"SAFE", "SUSPICIOUS", "PHISHING"}
    assert res_phish["threat_intelligence"]["status"] in {
        "CLEAN", "THREAT_DETECTED", "UNAVAILABLE", "ERROR"
    }
    assert res_phish["risk_assessment"]["final_status"] == res_phish["final_status"]
    print("    [V] Deteksi Phishing berhasil!")

    # 5. Test indikator heuristik yang eksplisit
    print("\n[5] Menguji Heuristic Detection...")
    heuristic_url = "https://8.8.8.8/download.exe"
    res_heuristic = scan_url(ScanRequest(url=heuristic_url))
    heuristic_rules = {
        finding["rule"]
        for finding in res_heuristic["heuristic_analysis"]["findings"]
    }
    assert "IP_ADDRESS_AS_HOSTNAME" in heuristic_rules
    assert "HIGH_RISK_FILE_EXTENSION" in heuristic_rules
    assert res_heuristic["heuristic_analysis"]["status"] == "PHISHING"
    print(f"    [+] Indikator ditemukan: {', '.join(sorted(heuristic_rules))}")
    print(f"    [+] Heuristic Status   : {res_heuristic['heuristic_analysis']['status']}")
    print("    [V] Heuristic Detection berhasil!")

    # 6. Test Keamanan & Anti-SSRF Protection
    print("\n[6] Menguji Fitur Keamanan & Anti-SSRF...")
    
    # Blokir localhost
    try:
        scan_url(ScanRequest(url="http://localhost:8000/internal-data"))
        assert False, "Harusnya memblokir localhost!"
    except HTTPException as e:
        assert e.status_code == 400
        print(f"    [+] SSRF localhost dicegah  : {e.detail}")

    # Blokir 127.0.0.1
    try:
        scan_url(ScanRequest(url="http://127.0.0.1:8080/secret"))
        assert False, "Harusnya memblokir loopback IP!"
    except HTTPException as e:
        assert e.status_code == 400
        print(f"    [+] SSRF loopback IP dicegah: {e.detail}")

    # Blokir Private IP 192.168.1.1
    try:
        scan_url(ScanRequest(url="http://192.168.1.1/admin-panel"))
        assert False, "Harusnya memblokir private IP!"
    except HTTPException as e:
        assert e.status_code == 400
        print(f"    [+] SSRF private IP dicegah : {e.detail}")

    print("\n" + "=" * 70)
    print("[V] SEMUA VALIDASI TAHAP 6 BERHASIL DENGAN SUKSES!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
