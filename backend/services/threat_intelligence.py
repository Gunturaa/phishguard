import logging
import os
import base64
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


class VirusTotalClient:
    """Passive VirusTotal URL reputation lookup using the public API."""

    ENDPOINT = "https://www.virustotal.com/api/v3/urls"

    def __init__(self, api_key: str | None = None, timeout_seconds: float = 5.0):
        self.api_key = api_key if api_key is not None else os.getenv("VIRUSTOTAL_API_KEY", "")
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _url_id(url: str) -> str:
        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
        return encoded.rstrip("=")

    def check_url(self, url: str) -> Dict[str, Any]:
        base_result = {"provider": "VirusTotal"}
        if not self.api_key:
            return {
                **base_result,
                "status": "UNAVAILABLE",
                "details": "VirusTotal API key belum dikonfigurasi di backend."
            }

        headers = {"x-apikey": self.api_key}
        endpoint = f"{self.ENDPOINT}/{self._url_id(url)}"
        try:
            response = requests.get(
                endpoint,
                headers=headers,
                timeout=self.timeout_seconds,
            )
            if response.status_code == 404:
                return {
                    **base_result,
                    "status": "NO_MATCH",
                    "details": "VirusTotal belum memiliki laporan untuk URL ini."
                }
            if response.status_code != 200:
                logger.warning("VirusTotal mengembalikan HTTP %s.", response.status_code)
                return {
                    **base_result,
                    "status": "ERROR",
                    "details": f"VirusTotal gagal memproses pemeriksaan (HTTP {response.status_code})."
                }

            body = response.json()
            stats = (
                body.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            if malicious or suspicious:
                return {
                    **base_result,
                    "status": "THREAT_DETECTED",
                    "details": "VirusTotal menemukan deteksi dari engine keamanan.",
                    "detections": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "total": sum(int(value or 0) for value in stats.values()),
                    },
                }
            return {
                **base_result,
                "status": "CLEAN",
                "details": "Tidak ada deteksi malicious atau suspicious pada laporan VirusTotal."
            }
        except requests.Timeout:
            logger.warning("VirusTotal timeout setelah %.1f detik.", self.timeout_seconds)
            return {
                **base_result,
                "status": "UNAVAILABLE",
                "details": "VirusTotal tidak merespons dalam batas waktu."
            }
        except requests.RequestException as exc:
            logger.warning("Permintaan VirusTotal gagal: %s", exc)
            return {
                **base_result,
                "status": "UNAVAILABLE",
                "details": "VirusTotal tidak dapat dihubungi."
            }
        except (ValueError, TypeError):
            logger.warning("Respons VirusTotal tidak valid.")
            return {
                **base_result,
                "status": "ERROR",
                "details": "Respons VirusTotal tidak valid."
            }


class ThreatIntelligenceClient:
    """Selects configured reputation providers without treating outages as clean."""

    def __init__(
        self,
        google_client: GoogleWebRiskClient | None = None,
        virustotal_client: VirusTotalClient | None = None,
    ):
        self.google = google_client or GoogleWebRiskClient()
        self.virustotal = virustotal_client or VirusTotalClient()

    def check_url(self, url: str) -> Dict[str, Any]:
        google_configured = bool(self.google.api_key)
        virustotal_configured = bool(self.virustotal.api_key)

        if google_configured:
            google_result = self.google.check_url(url)
            if virustotal_configured:
                return self._combine(google_result, self.virustotal.check_url(url))
            return google_result
        if virustotal_configured:
            return self.virustotal.check_url(url)
        return self.google.check_url(url)

    @staticmethod
    def _combine(*results: Dict[str, Any]) -> Dict[str, Any]:
        detected = [result for result in results if result.get("status") == "THREAT_DETECTED"]
        if detected:
            status = "THREAT_DETECTED"
            details = "Salah satu provider Threat Intelligence mendeteksi ancaman."
        elif all(result.get("status") == "CLEAN" for result in results):
            status = "CLEAN"
            details = "Tidak ada kecocokan ancaman pada provider yang dikonfigurasi."
        else:
            status = "UNAVAILABLE"
            details = "Sebagian provider Threat Intelligence tidak memberikan hasil."
        return {
            "provider": "Google Web Risk + VirusTotal",
            "status": status,
            "details": details,
            "providers": list(results),
        }


google_web_risk = GoogleWebRiskClient()
virustotal = VirusTotalClient()
threat_intelligence = ThreatIntelligenceClient(google_web_risk, virustotal)
