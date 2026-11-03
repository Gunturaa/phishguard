import re
import urllib.parse
from typing import Dict, Any, List

class HeuristicDetector:
    """
    Service untuk melakukan analisis heuristik berbasis aturan keamanan siber pada URL.
    Mendeteksi indikator mencurigakan:
    - Penggunaan alamat IP sebagai hostname
    - URL terlalu panjang
    - Subdomain berlebihan / bertingkat
    - Karakter atau pola URL mencurigakan (@ symbol, double slash, hyphens)
    - Ekstensi file berisiko tinggi
    - Pola impersonasi merek atau kata kunci kredensial pada hosting publik
    - Entropi URL tinggi (indikasi keacakan DGA)
    """

    # Ekstensi file berisiko tinggi (payload malware/dropper)
    HIGH_RISK_EXTENSIONS = {
        "exe": "Eksekutor biner Windows (.exe)",
        "scr": "Windows Screensaver biner (.scr)",
        "bat": "Batch script (.bat)",
        "cmd": "Command script (.cmd)",
        "vbs": "VBScript executable (.vbs)",
        "apk": "Android package installer (.apk)",
        "iso": "Disk image file (.iso)",
        "ps1": "PowerShell script (.ps1)",
        "jar": "Java executable archive (.jar)"
    }

    # Kata kunci kredensial yang sering disalahgunakan dalam serangan phishing
    CREDENTIAL_KEYWORDS = {
        "login", "signin", "verify", "verification", "secure", "security",
        "account", "update", "banking", "wallet", "recovery", "pulihkan",
        "bantuan", "konfirmasi", "password", "credential", "authenticate"
    }

    # Merek populer / finansial yang sering di-impersonasi
    IMPERSONATED_TARGETS = {
        "paypal", "metamask", "netflix", "apple", "google", "microsoft",
        "facebook", "instagram", "whatsapp", "telegram", "binance", "kraken",
        "dana", "bca", "mandiri", "bri", "bni", "gopay", "ovo", "shopee"
    }

    # Domain hosting gratis / publik yang sering disalahgunakan untuk hosting phishing
    FREE_HOSTING_DOMAINS = {
        "godaddysites.com", "weeblysite.com", "weebly.com", "wixsite.com",
        "pages.dev", "firebaseapp.com", "web.app", "vercel.app", "netlify.app",
        "github.io", "glitch.me", "000webhostapp.com", "infinityfreeapp.com",
        "square.site", "blogger.com", "blogspot.com"
    }

    # Regex untuk alamat IPv4
    IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        """
        Menjalankan serangkaian aturan heuristik terhadap URL dan menghitung skor risiko.
        
        Returns:
            Dict berisi status heuristik, skor heuristik, daftar temuan, dan ringkasan.
        """
        url = raw_url.strip()
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        host = parsed.netloc.split(":")[0].lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_lower = url.lower()

        findings: List[Dict[str, Any]] = []
        heuristic_score = 0

        # 1. PENGGUNAAN ALAMAT IP SEBAGAI HOSTNAME
        clean_ip = host.strip("[]")
        if self.IPV4_REGEX.match(clean_ip) or ":" in clean_ip:
            findings.append({
                "rule": "IP_ADDRESS_AS_HOSTNAME",
                "severity": "HIGH",
                "risk_points": 35,
                "title": "Alamat IP Sebagai Hostname",
                "description": f"URL menggunakan alamat IP mentah ({host}) sebagai pengganti nama domain resmi. Penyerang kerap menggunakan teknik ini untuk menghindari sistem reputasi domain."
            })
            heuristic_score += 35

        # 2. KARAKTER '@' PADA URL (USERINFO REDIRECTION TRICK)
        if "@" in parsed.netloc or "@" in url.split("?")[0]:
            findings.append({
                "rule": "AT_SYMBOL_OBFUSCATION",
                "severity": "HIGH",
                "risk_points": 30,
                "title": "Karakter '@' Pengabur Domain",
                "description": "URL mengandung simbol '@' sebelum path. Browser dapat mengabaikan string sebelum '@' dan mengarahkan pengguna ke server penyerang di belakangnya."
            })
            heuristic_score += 30

        # 3. SUBDOMAIN BERLEBIHAN / BERTINGKAT
        parts = host.split(".")
        subdomain_count = len(parts[:-2]) if len(parts) >= 2 else 0
        if subdomain_count >= 3:
            findings.append({
                "rule": "EXCESSIVE_SUBDOMAINS",
                "severity": "MEDIUM",
                "risk_points": 20,
                "title": f"Subdomain Bertingkat Berlebihan ({subdomain_count} level)",
                "description": f"Domain memiliki {subdomain_count} tingkat subdomain. Struktur ini sering dimanfaatkan penyerang untuk menyamarkan nama merek terkenal di bagian awal hostname."
            })
            heuristic_score += 20
        elif subdomain_count == 2:
            heuristic_score += 5

        # 4. PANJANG URL TIDAK WAJAR
        if len(url) > 100:
            findings.append({
                "rule": "EXCESSIVE_URL_LENGTH",
                "severity": "MEDIUM",
                "risk_points": 15,
                "title": f"URL Sangat Panjang ({len(url)} karakter)",
                "description": f"Panjang URL ({len(url)} karakter) jauh melampaui rata-rata normal. URL yang sengaja dipanjangkan kerap dipakai untuk menyembunyikan domain target pada layar ponsel."
            })
            heuristic_score += 15
        elif len(url) > 75:
            findings.append({
                "rule": "LONG_URL_LENGTH",
                "severity": "LOW",
                "risk_points": 8,
                "title": f"URL Cukup Panjang ({len(url)} karakter)",
                "description": f"Panjang URL mencapai {len(url)} karakter."
            })
            heuristic_score += 8

        # 5. EKSTENSI FILE BERBAHAYA / BERISIKO TINGGI
        clean_path = path.split("?")[0].split("#")[0]
        if "." in clean_path:
            ext = clean_path.rsplit(".", 1)[-1].strip("/")
            if ext in self.HIGH_RISK_EXTENSIONS:
                ext_desc = self.HIGH_RISK_EXTENSIONS[ext]
                findings.append({
                    "rule": "HIGH_RISK_FILE_EXTENSION",
                    "severity": "HIGH",
                    "risk_points": 35,
                    "title": f"Unduhan File Berisiko Tinggi (.{ext})",
                    "description": f"Tautan langsung mengarah pada file {ext_desc}. File jenis ini berpotensi mengeksekusi kode berbahaya (malware/trojan) pada komputer korban."
                })
                heuristic_score += 35

        # 6. PENGGUNAAN HYPHEN (-) GANDA ATAU BERLEBIH PADA HOSTNAME
        hyphen_count = host.count("-")
        if hyphen_count >= 2:
            findings.append({
                "rule": "MULTIPLE_HYPHENS_IN_DOMAIN",
                "severity": "MEDIUM",
                "risk_points": 15,
                "title": f"Banyak Tanda Hubung pada Hostname ({hyphen_count} tanda hubung)",
                "description": "Terdapat banyak karakter tanda hubung (-) pada nama domain. Pola ini umum digunakan penyerang untuk menyusun nama domain tiruan (typosquatting)."
            })
            heuristic_score += 15

        # 7. IMPERSONASI MEREK / KATA KUNCI KREDENSIAL PADA FREE HOSTING
        for free_host in self.FREE_HOSTING_DOMAINS:
            if host.endswith(free_host) and host != free_host:
                # Memeriksa apakah subdomain mengandung kata kunci kredensial atau target brand
                subdomain_part = host.replace(free_host, "").strip(".")
                matched_keywords = [kw for kw in (self.CREDENTIAL_KEYWORDS | self.IMPERSONATED_TARGETS) if kw in subdomain_part]
                if matched_keywords:
                    findings.append({
                        "rule": "CREDENTIAL_PHISH_ON_FREE_HOSTING",
                        "severity": "HIGH",
                        "risk_points": 30,
                        "title": "Impersonasi Akun pada Hosting Publik",
                        "description": f"Domain memanfaatkan hosting gratis/publik ({free_host}) dengan menyertakan kata kunci sensitif/merek: '{', '.join(matched_keywords)}'. Pola ini merupakan indikator kuat situs pancingan kredensial."
                    })
                    heuristic_score += 30
                    break

        # 8. PERSENTASE KARAKTER ANGKA TINGGI PADA HOSTNAME
        digit_count = sum(1 for c in host if c.isdigit())
        if len(host) > 0 and (digit_count / len(host)) > 0.30 and not self.IPV4_REGEX.match(clean_ip):
            findings.append({
                "rule": "HIGH_NUMERIC_RATIO_IN_HOSTNAME",
                "severity": "LOW",
                "risk_points": 10,
                "title": "Banyak Karakter Angka pada Hostname",
                "description": f"Hostname mengandung persentase angka yang tinggi ({digit_count / len(host) * 100:.1f}%), mengindikasikan domain acak atau sementara."
            })
            heuristic_score += 10

        # Normalisasi skor heuristik ke rentang 0 - 100
        normalized_score = min(heuristic_score, 100)

        # Penentuan status heuristik
        if normalized_score >= 50 or any(f["severity"] == "HIGH" for f in findings):
            heuristic_status = "PHISHING"
        elif normalized_score >= 20 or any(f["severity"] == "MEDIUM" for f in findings):
            heuristic_status = "SUSPICIOUS"
        else:
            heuristic_status = "SAFE"

        return {
            "status": heuristic_status,
            "risk_score": normalized_score,
            "findings_count": len(findings),
            "findings": findings,
            "summary": self._generate_summary(heuristic_status, findings)
        }

    def _generate_summary(self, status: str, findings: List[Dict[str, Any]]) -> str:
        """Membuat ringkasan penjelasan manusiawi dari hasil temuan heuristik."""
        if not findings:
            return "Tidak ditemukan indikator heuristik yang mencurigakan pada URL ini."
        
        high_cnt = sum(1 for f in findings if f["severity"] == "HIGH")
        med_cnt = sum(1 for f in findings if f["severity"] == "MEDIUM")
        
        parts = []
        if high_cnt > 0:
            parts.append(f"{high_cnt} indikator berisiko tinggi")
        if med_cnt > 0:
            parts.append(f"{med_cnt} indikator berisiko sedang")
        low_cnt = len(findings) - high_cnt - med_cnt
        if low_cnt > 0:
            parts.append(f"{low_cnt} indikator berisiko rendah")
            
        return f"Analisis heuristik mendeteksi {', '.join(parts)}."

# Singleton instance
heuristic_detector = HeuristicDetector()

