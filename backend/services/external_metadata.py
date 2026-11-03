import ipaddress
import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
import tldextract

logger = logging.getLogger("phishguard.external_metadata")


class _TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)

    def value(self) -> str:
        return " ".join(" ".join(self.title_parts).split())[:300]


def _is_public_hostname(hostname: str) -> bool:
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        return False
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except socket.gaierror:
        return False
    return bool(addresses) and all(
        not (
            (ip := ipaddress.ip_address(address)).is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
        for address in addresses
    )


def _result(status: str, value: Any = None, details: Optional[str] = None) -> Dict[str, Any]:
    return {"status": status, "value": value, "details": details}


class ExternalMetadataClient:
    def __init__(self) -> None:
        self.timeout = float(os.getenv("METADATA_TIMEOUT_SECONDS", "5"))
        self.enabled = os.getenv("ENABLE_EXTERNAL_METADATA", "true").lower() == "true"

    def collect(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        extracted = tldextract.extract(hostname)
        registrable_domain = extracted.registered_domain or hostname
        unavailable = "Pemeriksaan metadata eksternal dinonaktifkan."
        if not self.enabled:
            return self._empty(unavailable)
        if not _is_public_hostname(hostname):
            return self._empty("Hostname tidak dapat diverifikasi sebagai alamat publik.")

        session = requests.Session()
        session.headers["User-Agent"] = "PHISHGUARD-Metadata/1.0"

        # Parallelize network requests using ThreadPoolExecutor for responsive scans
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_page = executor.submit(self._fetch_page, session, url)
            future_rdap = executor.submit(self._rdap, session, registrable_domain)
            future_popularity = executor.submit(self._popularity, session, registrable_domain)

            try:
                redirect, title = future_page.result(timeout=self.timeout + 1.0)
            except Exception:
                redirect, title = _result("ERROR", None, "Pemeriksaan halaman gagal."), _result("UNAVAILABLE", None, "Page title tidak dapat diambil.")

            try:
                age, explanation = future_rdap.result(timeout=self.timeout + 1.0)
            except Exception:
                age, explanation = _result("ERROR", None, "Layanan RDAP gagal."), _result("UNAVAILABLE", None, "Penjelasan domain tidak tersedia.")

            try:
                popularity = future_popularity.result(timeout=self.timeout + 1.0)
            except Exception:
                popularity = _result("ERROR", None, "Ranking publik tidak dapat dihubungi.")

        return {
            "redirects": redirect,
            "domain_age": age,
            "domain_explanation": explanation,
            "popularity": popularity,
            "page_title": title,
        }

    def _fetch_page(self, session: requests.Session, url: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
        try:
            response = session.get(url, timeout=self.timeout, allow_redirects=False, stream=True)
            location = response.headers.get("location")
            redirect = _result(
                "AVAILABLE",
                location or "No redirection",
                "Redirect diperiksa tanpa mengikuti tujuan redirect."
            )
            if response.status_code in {301, 302, 303, 307, 308}:
                return redirect, _result("UNAVAILABLE", None, "Page title tidak diambil karena respons mengarahkan ke URL lain.")

            content_type = response.headers.get("content-type", "").lower()
            if "text/html" not in content_type:
                return redirect, _result("UNAVAILABLE", None, "Respons bukan halaman HTML.")

            body = b""
            for chunk in response.iter_content(chunk_size=8192):
                body += chunk
                if len(body) >= 512 * 1024:
                    break
            parser = _TitleParser()
            parser.feed(body.decode(response.encoding or "utf-8", errors="ignore"))
            title = parser.value()
            return redirect, _result("AVAILABLE" if title else "UNAVAILABLE", title or None, "Judul HTML berhasil dibaca." if title else "Tag title tidak ditemukan.")
        except requests.Timeout:
            return _result("ERROR", None, "Pemeriksaan halaman timeout."), _result("ERROR", None, "Pemeriksaan halaman timeout.")
        except requests.RequestException as exc:
            logger.warning("Metadata halaman gagal: %s", exc)
            return _result("ERROR", None, "Halaman tidak dapat diakses."), _result("ERROR", None, "Halaman tidak dapat diakses.")

    def _rdap(self, session: requests.Session, hostname: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
        try:
            tld = hostname.rsplit(".", 1)[-1].lower()
            endpoints = [
                f"https://rdap.org/domain/{hostname}",
                f"https://rdap.verisign.com/{tld}/v1/domain/{hostname}",
            ]
            response = None
            for endpoint in endpoints:
                candidate = session.get(endpoint, timeout=self.timeout)
                if candidate.status_code == 200:
                    response = candidate
                    break
                response = candidate
            if response is None or response.status_code != 200:
                code = response.status_code if response is not None else "unknown"
                return _result("ERROR", None, f"RDAP mengembalikan HTTP {code}."), _result("UNAVAILABLE", None, "Penjelasan domain tidak tersedia dari RDAP.")
            data = response.json()
            registration = next(
                (event.get("eventDate") for event in data.get("events", []) if event.get("eventAction") in {"registration", "created"}),
                None,
            )
            age = None
            if registration:
                created = datetime.fromisoformat(registration.replace("Z", "+00:00"))
                years = (datetime.now(timezone.utc) - created).days // 365
                age = f"{max(0, years)} years old"
            entities = [entity.get("roles", []) for entity in data.get("entities", [])]
            explanation = f"RDAP mencatat domain {hostname} sebagai domain terdaftar."
            if any("registrant" in roles for roles in entities):
                explanation += " Data registrant tersedia melalui layanan RDAP."
            return _result("AVAILABLE" if age else "UNAVAILABLE", age, "Usia dihitung dari tanggal registrasi RDAP." if age else "Tanggal registrasi tidak tersedia."), _result("AVAILABLE", explanation, "Ringkasan berbasis metadata RDAP; bukan penilaian reputasi.")
        except (requests.RequestException, ValueError, TypeError):
            return _result("ERROR", None, "Layanan RDAP tidak dapat memberikan data domain."), _result("UNAVAILABLE", None, "Penjelasan domain tidak tersedia.")

    def _popularity(self, session: requests.Session, hostname: str) -> Dict[str, Any]:
        try:
            response = session.get(f"https://tranco-list.eu/api/ranks/domain/{hostname}", timeout=self.timeout)
            if response.status_code != 200:
                return _result("ERROR", None, "Ranking publik tidak tersedia.")
            data = response.json()
            rank = data.get("rank") if isinstance(data, dict) else None
            if not rank:
                return _result("AVAILABLE", "Not ranked", "Domain tidak ditemukan dalam ranking Tranco.")
            label = "Popular" if rank <= 100_000 else "Less popular"
            return _result("AVAILABLE", f"{label} (Tranco rank #{rank:,})", "Berdasarkan ranking Tranco.")
        except (requests.RequestException, ValueError, TypeError):
            return _result("ERROR", None, "Ranking publik tidak dapat dihubungi.")

    def _empty(self, details: str) -> Dict[str, Any]:
        return {key: _result("UNAVAILABLE", None, details) for key in ("redirects", "domain_age", "domain_explanation", "popularity", "page_title")}


external_metadata = ExternalMetadataClient()
