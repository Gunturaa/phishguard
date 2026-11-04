import os
import ipaddress
import logging
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from services.feature_extractor import extract_features
from services.heuristic_detector import heuristic_detector
from services.ml_detector import ml_detector
from services.risk_assessment import risk_assessor
from services.scan_metadata import build_scan_metadata
from services.external_metadata import external_metadata
from services.threat_intelligence import threat_intelligence
from services.web_vulnerability_checker import web_vulnerability_checker
from services.scan_storage import scan_storage
from services.report_generator import build_pdf
from services.notifications import notify_discord

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishguard.main")

app = FastAPI(
    title="PHISHGUARD API",
    description="Hybrid AI-Based Phishing URL Detection System",
    version="1.0.0"
)

# Konfigurasi CORS
origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="URL yang akan dianalisis keamanannya"
    )

class WebVulnerabilityRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)
    authorized: bool = Field(
        ...,
        description="Harus true: pemohon memiliki atau berwenang menguji target."
    )

class MLResult(BaseModel):
    status: str
    predicted_class: Optional[int] = None
    confidence: float
    probabilities: Dict[str, float]
    model_loaded: bool = True

class HeuristicResult(BaseModel):
    status: str
    risk_score: int
    findings_count: int
    findings: List[Dict[str, Any]] = []
    summary: str

class ThreatIntelResult(BaseModel):
    status: str
    provider: str
    details: Optional[str] = None

class ScanResponse(BaseModel):
    ok: bool
    history_id: Optional[int] = None
    url: str
    final_status: str
    risk_score: Optional[int] = None
    machine_learning: MLResult
    heuristic_analysis: HeuristicResult
    threat_intelligence: ThreatIntelResult
    extracted_features: Optional[Dict[str, Any]] = None
    recommendations: List[str]
    disclaimer: str
    risk_assessment: Dict[str, Any]
    scan_metadata: Dict[str, Any]

def validate_and_sanitize_url(raw_url: str) -> str:
    """
    Validasi dan sanitasi URL sebelum diproses:
    1. Memastikan tidak kosong dan panjang wajar.
    2. Menghindari spasi atau karakter ilegal.
    3. Proteksi SSRF (mencegah localhost, 127.0.0.1, private IP, loopback).
    """
    val = raw_url.strip()
    if not val:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL tidak boleh kosong."
        )

    if any(ch.isspace() for ch in val):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL tidak boleh mengandung spasi."
        )

    # Tambahkan skema jika belum disertakan
    candidate = val if "://" in val else f"https://{val}"
    try:
        parsed = urlparse(candidate)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Format URL tidak valid: {str(exc)}"
        )

    if parsed.scheme.lower() not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Hanya protokol HTTP atau HTTPS yang didukung."
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Format domain URL tidak valid."
        )

    # Anti-SSRF: Blokir akses ke localhost atau private network
    lower_host = hostname.lower()
    if lower_host in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pemindaian alamat internal / localhost tidak diizinkan demi keamanan."
        )

    try:
        ip_obj = ipaddress.ip_address(lower_host)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Pemindaian IP private / internal network tidak diizinkan demi keamanan."
            )
    except ValueError:
        # Hostname adalah domain name (bukan IP address langsung), lanjutkan
        pass

    return candidate

@app.get("/")
def root():
    return {
        "name": "PHISHGUARD API",
        "description": "Hybrid AI-Based Phishing URL Detection System",
        "version": "1.0.0",
        "status": "online"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "phishguard-backend",
        "ml_model_ready": ml_detector.is_ready(),
        "total_features": len(ml_detector.feature_names)
    }

@app.get("/history")
def scan_history(limit: int = 20):
    return {"items": scan_storage.list_recent(limit)}

@app.get("/history/{record_id}")
def scan_history_detail(record_id: int):
    record = scan_storage.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Riwayat scan tidak ditemukan.")
    return record

@app.get("/history/{record_id}/report.pdf")
def scan_history_report(record_id: int):
    record = scan_storage.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Riwayat scan tidak ditemukan.")
    pdf = build_pdf("PHISHGUARD Security Report", record["result"])
    return StreamingResponse(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="phishguard-report-{record_id}.pdf"'},
    )

@app.post("/web-vuln-check")
def web_vulnerability_check(payload: WebVulnerabilityRequest):
    """Passive, non-exploitative checks for an explicitly authorized target."""
    if not payload.authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Konfirmasi otorisasi diperlukan untuk pemeriksaan keamanan web."
        )
    normalized_url = validate_and_sanitize_url(payload.url)
    result = web_vulnerability_checker.check(normalized_url)
    scan_storage.save(
        "web_vulnerability",
        normalized_url,
        result.get("status", "UNKNOWN"),
        result,
    )
    if result.get("risk_level") in {"High", "Medium"}:
        notify_discord("Passive vulnerability result", result)
    return result

@app.post("/scan", response_model=ScanResponse)
def scan_url(payload: ScanRequest):
    """
    Endpoint utama pemindaian URL.
    Tahap 2 mengintegrasikan Machine Learning Random Forest Classifier secara penuh.
    Threat Intelligence dijalankan sebagai pemeriksaan terpisah dan tidak
    menganggap kegagalan provider sebagai URL aman.
    """
    normalized_url = validate_and_sanitize_url(payload.url)

    # 1. Ekstraksi 16 Fitur URL (Sesuai dataset LegitPhish)
    features = extract_features(normalized_url)

    # 2. Prediksi Machine Learning
    ml_output = ml_detector.predict(features)

    # Analisis heuristik dijalankan terpisah dari prediksi ML.
    heuristic_output = heuristic_detector.analyze(normalized_url)
    threat_output = threat_intelligence.check_url(normalized_url)
    scan_metadata = build_scan_metadata(normalized_url)
    scan_metadata.update(external_metadata.collect(normalized_url))

    assessment = risk_assessor.assess(
        ml_output,
        heuristic_output,
        threat_output,
        normalized_url,
    )
    final_status = assessment["final_status"]
    risk_score = assessment["risk_score"]

    if final_status == "PHISHING":
        recommendations = [
            "Peringatan: hasil gabungan menunjukkan URL ini memiliki risiko phishing tinggi.",
            "JANGAN memasukkan username, password, nomor kartu kredit, atau kode OTP pada tautan ini.",
            "Verifikasi keaslian alamat situs resmi sebelum berinteraksi lebih lanjut."
        ]
    elif final_status == "SAFE":
        recommendations = [
            "Tidak ada indikator risiko tinggi dari pemeriksaan yang tersedia.",
            "Tetap periksa alamat website sebelum memasukkan informasi pribadi."
        ]
    else:
        recommendations = [
            "Hasil pemeriksaan menunjukkan sinyal yang perlu diwaspadai.",
            "Hindari memasukkan data sensitif sampai URL terverifikasi."
        ]

    result = {
        "ok": True,
        "url": normalized_url,
        "final_status": final_status,
        "risk_score": risk_score,
        "machine_learning": ml_output,
        "heuristic_analysis": heuristic_output,
        "threat_intelligence": threat_output,
        "extracted_features": features,
        "recommendations": recommendations,
        "risk_assessment": assessment,
        "scan_metadata": scan_metadata,
        "disclaimer": "PHISHGUARD menggunakan analisis berbasis AI untuk deteksi risiko. Hasil ini adalah indikasi keamanan dan bukan jaminan mutlak."
    }
    history_id = scan_storage.save("url_scan", normalized_url, final_status, result, risk_score)
    result["history_id"] = history_id
    return result
