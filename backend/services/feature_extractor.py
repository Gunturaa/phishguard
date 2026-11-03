import re
import math
import collections
import urllib.parse
from typing import Dict, Any

# Ekstensi file yang sering digunakan dalam payload berbahaya pada dataset LegitPhish
SUSPICIOUS_EXTENSIONS = {"exe", "zip", "apk", "cmd", "bin", "js"}

# TLD populer global yang teridentifikasi pada dataset LegitPhish
POPULAR_TLDS = {"com", "net", "org", "edu", "gov"}

# Regex pencocokan IPv4 pada URL
IPV4_REGEX = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

def calculate_shannon_entropy(text: str) -> float:
    """
    Menghitung Shannon Entropy berbasis log2 dari string URL.
    Formula: H = -sum(p * log2(p)) untuk setiap karakter unik.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = collections.Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 9)

def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Mengekstrak 16 fitur URL yang 100% konsisten dengan definisi dataset LegitPhish.
    
    Daftar 16 Fitur:
    1.  url_length                 : Panjang string URL
    2.  has_ip_address             : Flag 1 jika URL mengandung pola alamat IPv4, 0 jika tidak
    3.  dot_count                  : Jumlah titik (.) pada URL
    4.  https_flag                 : Flag 1 jika protokol adalah https, 0 jika tidak
    5.  url_entropy                : Nilai Shannon Entropy URL
    6.  token_count                : Jumlah token dengan pemisah [/.\?#=]
    7.  subdomain_count            : Jumlah subdomain (-1 jika netloc kosong)
    8.  query_param_count          : Jumlah parameter query string
    9.  tld_length                 : Panjang karakter TLD (bagian setelah titik terakhir pada netloc)
    10. path_length                : Panjang path URL
    11. has_hyphen_in_domain       : Flag 1 jika terdapat hyphen (-) pada netloc/domain
    12. number_of_digits           : Jumlah karakter numerik (0-9) di seluruh URL
    13. tld_popularity             : Flag 1 jika TLD termasuk com, net, org, edu, gov
    14. suspicious_file_extension  : Flag 1 jika terdapat ekstensi exe, zip, apk, cmd, bin, js
    15. domain_name_length         : Panjang nama domain utama
    16. percentage_numeric_chars   : Persentase karakter angka terhadap panjang URL
    """
    url = raw_url.strip()
    parsed = urllib.parse.urlparse(url)

    # 1. url_length
    url_length = len(url)

    # 2. has_ip_address
    has_ip = 1 if IPV4_REGEX.search(url) else 0

    # 3. dot_count
    dot_count = url.count(".")

    # 4. https_flag
    https_flag = 1 if parsed.scheme.lower() == "https" else 0

    # 5. url_entropy
    url_entropy = calculate_shannon_entropy(url)

    # 6. token_count
    tokens = re.split(r"[/.\?#=]", url)
    token_count = len(tokens)

    # Analisis domain / netloc
    netloc = parsed.netloc
    if not netloc:
        subdomain_count = -1
        domain_name_length = 0
        tld_length = 0
        has_hyphen_in_domain = 0
        tld_popularity = 0
    else:
        parts = netloc.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            domain = parts[-2]
            subdomains = parts[:-2]
            subdomain_count = len(subdomains)
            domain_name_length = len(domain)
            tld_length = len(tld)
            has_hyphen_in_domain = 1 if "-" in netloc else 0
            tld_popularity = 1 if tld.lower().split(":")[0] in POPULAR_TLDS else 0
        else:
            domain = netloc
            subdomain_count = 0
            domain_name_length = len(domain)
            tld_length = 0
            has_hyphen_in_domain = 1 if "-" in netloc else 0
            tld_popularity = 0

    # 8. query_param_count
    if "?" in url:
        query_part = url.split("?", 1)[1].replace("&amp;", "&")
        query_param_count = len(query_part.split("&"))
    else:
        query_param_count = 1

    # 10. path_length
    path_length = len(parsed.path)

    # 12. number_of_digits
    number_of_digits = sum(1 for c in url if c.isdigit())

    # 14. suspicious_file_extension
    path_lower = parsed.path.lower()
    suspicious_file_extension = 0
    for ext in SUSPICIOUS_EXTENSIONS:
        if path_lower.endswith("." + ext) or ("." + ext + "/" in path_lower) or ("." + ext + "?" in url.lower()):
            suspicious_file_extension = 1
            break

    # 16. percentage_numeric_chars
    percentage_numeric_chars = (number_of_digits / url_length * 100.0) if url_length > 0 else 0.0

    return {
        "url_length": int(url_length),
        "has_ip_address": int(has_ip),
        "dot_count": int(dot_count),
        "https_flag": int(https_flag),
        "url_entropy": float(url_entropy),
        "token_count": int(token_count),
        "subdomain_count": int(subdomain_count),
        "query_param_count": int(query_param_count),
        "tld_length": int(tld_length),
        "path_length": int(path_length),
        "has_hyphen_in_domain": int(has_hyphen_in_domain),
        "number_of_digits": int(number_of_digits),
        "tld_popularity": int(tld_popularity),
        "suspicious_file_extension": int(suspicious_file_extension),
        "domain_name_length": int(domain_name_length),
        "percentage_numeric_chars": round(float(percentage_numeric_chars), 6)
    }
