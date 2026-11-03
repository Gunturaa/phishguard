import base64
import os
from typing import Any, Dict
from urllib.parse import urlparse


def build_scan_metadata(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    virus_total_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    return {
        "scanned_url": url,
        "domain": hostname,
        "whois_url": f"https://www.whois.com/whois/{hostname}",
        "virustotal_url": f"https://www.virustotal.com/gui/url/{virus_total_id}",
        "redirects": {
            "status": "NOT_CHECKED",
            "value": None,
            "details": "Redirect tidak diikuti atau diperiksa oleh PHISHGUARD."
        },
        "domain_age": {
            "status": "UNAVAILABLE",
            "value": None,
            "details": "Informasi usia domain belum tersedia."
        },
        "domain_explanation": {
            "status": "UNAVAILABLE",
            "value": None,
            "details": "Penjelasan domain belum tersedia."
        },
        "popularity": {
            "status": "UNAVAILABLE",
            "value": None,
            "details": "Data popularitas belum tersedia."
        },
        "viewed_as": "Desktop",
        "scanned_from": os.getenv("SCAN_LOCATION_LABEL", "Not specified"),
        "scanned_with": "PHISHGUARD Hybrid Scanner",
        "scanner_version": "1.0.0",
        "page_title": {
            "status": "NOT_CHECKED",
            "value": None,
            "details": "Judul halaman tidak diambil karena PHISHGUARD tidak mengunjungi URL."
        },
    }
