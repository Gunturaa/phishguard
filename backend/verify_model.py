"""
PHISHGUARD - Model Verification Script
Script untuk memverifikasi model Random Forest dan daftar fitur pada Tahap 1.
"""

import os
import pickle
import joblib

def verify():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, "models", "phishguard_model.pkl")
    features_path = os.path.join(base_dir, "models", "phishguard_features.pkl")

    print("[*] Memeriksa keberadaan file model & fitur...")
    if not os.path.exists(model_path):
        print(f"[-] File model TIDAK DITEMUKAN di: {model_path}")
        return False
    if not os.path.exists(features_path):
        print(f"[-] File fitur TIDAK DITEMUKAN di: {features_path}")
        return False

    print(f"[+] File model ditemukan: {model_path} ({os.path.getsize(model_path):,} bytes)")
    print(f"[+] File fitur ditemukan: {features_path} ({os.path.getsize(features_path):,} bytes)")

    print("\n[*] Membaca daftar fitur (phishguard_features.pkl)...")
    with open(features_path, "rb") as f:
        features = pickle.load(f)
    print(f"[+] Total fitur: {len(features)}")
    for idx, feat in enumerate(features, 1):
        print(f"    {idx:2d}. {feat}")

    print("\n[*] Memuat model Random Forest (phishguard_model.pkl)...")
    model = joblib.load(model_path)
    print(f"[+] Tipe model : {type(model).__name__}")
    print(f"[+] Kelas target: {model.classes_} (0 = Phishing, 1 = Legitimate)")
    print(f"[+] Fitur input : {model.n_features_in_} fitur diharapkan")

    # Uji coba inferensi dummy dengan 16 fitur bernilai 0
    dummy_input = [[0] * len(features)]
    pred = model.predict(dummy_input)
    proba = model.predict_proba(dummy_input)[0]
    print("\n[*] Uji coba prediksi dummy (16 fitur nol):")
    print(f"    Prediksi kelas: {pred[0]}")
    print(f"    Probabilitas  : Class 0 (Phishing)={proba[0]:.4f}, Class 1 (Legit)={proba[1]:.4f}")

    print("\n[V] VERIFIKASI TAHAP 1 BERHASIL! Model dan fitur siap diintegrasikan ke FastAPI.")
    return True

if __name__ == "__main__":
    verify()

