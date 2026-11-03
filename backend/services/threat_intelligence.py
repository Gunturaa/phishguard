import logging
import os
from typing import Any, Dict

import requests

logger = logging.getLogger("phishguard.threat_intelligence")


class GoogleWebRiskClient:
    """Read-only Google Web Risk lookup for submitted URLs."""

    ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"
    THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")

    def __init__(self, api_key: str | None = None, timeout_seconds: float = 5.0):
        self.api_key = api_key if api_key is not None else os.getenv("GOOGLE_WEB_RISK_API_KEY", "")
        self.timeout_seconds = timeout_seconds

    def check_url(self, url: str) -> Dict[str, Any]:
        base_result = {"provider": "Google Web Risk"}
        if not self.api_key:
            return {
                **base_result,
                "status": "UNAVAILABLE",
                "details": "Google Web Risk API key belum dikonfigurasi di backend."
            }

        params = [("key", self.api_key), ("uri", url)]
        params.extend(("threatTypes", threat_type) for threat_type in self.THREAT_TYPES)

        try:
            response = requests.get(
                self.ENDPOINT,
                params=params,
                timeout=self.timeout_seconds,
            )
            if response.status_code == 200:
                body = response.json()
                threats = body.get("threat", [])
                if threats:
                    return {
                        **base_result,
                        "status": "THREAT_DETECTED",
                        "details": "Google Web Risk mendeteksi URL ini sebagai ancaman.",
                        "threat_types": [
                            item.get("threatTypes", [])
                            for item in threats
                            if isinstance(item, dict)
                        ],
                    }
                return {
                    **base_result,
                    "status": "CLEAN",
                    "details": "Google Web Risk tidak menemukan kecocokan ancaman yang diketahui."
                }

            logger.warning("Google Web Risk mengembalikan HTTP %s.", response.status_code)
            return {
                **base_result,
                "status": "ERROR",
                "details": f"Google Web Risk gagal memproses pemeriksaan (HTTP {response.status_code})."
            }
        except requests.Timeout:
            logger.warning("Google Web Risk timeout setelah %.1f detik.", self.timeout_seconds)
            return {
                **base_result,
                "status": "UNAVAILABLE",
                "details": "Google Web Risk tidak merespons dalam batas waktu."
            }
        except requests.RequestException as exc:
            logger.warning("Permintaan Google Web Risk gagal: %s", exc)
            return {
                **base_result,
                "status": "UNAVAILABLE",
                "details": "Google Web Risk tidak dapat dihubungi."
            }
        except ValueError:
            logger.warning("Respons Google Web Risk bukan JSON yang valid.")
            return {
                **base_result,
                "status": "ERROR",
                "details": "Respons Google Web Risk tidak valid."
            }


google_web_risk = GoogleWebRiskClient()
