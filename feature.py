import re
import math
import tldextract
import ipaddress
import pandas as pd
from urllib.parse import urlparse, parse_qs

#popular TLD diambil dari data IANA Root Zone Database November 2025
POPULAR_TLDS = {
    "com","cn","de","net","org","uk","ru","nl","br",
    "au","fr","in","eu"
}

SUSPICIOUS_EXTENSIONS = {
    ".exe",".zip",".rar",".apk",".js",".iso",
    ".scr",".bat",".cmd",".ps1",".7z",".vbs",".jar"
}

def shannon_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    domain = ext.domain.lower()
    suffix = ext.suffix.lower()

    features = {}

    # URL (text)
    features["URL"] = url

    # 1. URL length
    features["url_length"] = len(url)

    # 2. Has IP address
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
        features["has_ip_address"] = 1
    except:
        features["has_ip_address"] = 0

    # 3. Dot count
    features["dot_count"] = url.count(".")

    # 4. HTTPS flag
    features["https_flag"] = 1 if parsed.scheme == "https" else 0

    # 5. URL entropy
    features["url_entropy"] = shannon_entropy(url)

    # 6. Token count
    tokens = re.split(r"[./?=&:_-]", url)
    features["token_count"] = len([t for t in tokens if t])

    # 7. Subdomain count
    features["subdomain_count"] = len(ext.subdomain.split(".")) if ext.subdomain else 0

    # 8. Query param count
    features["query_param_count"] = len(parse_qs(parsed.query))

    # 9. TLD length
    features["tld_length"] = len(suffix.replace(".", ""))

    # 10. Path length
    features["path_length"] = len(parsed.path)

    # 11. Has hyphen in domain
    features["has_hyphen_in_domain"] = 1 if "-" in domain else 0

    # 12. Number of digits
    features["number_of_digits"] = sum(c.isdigit() for c in url)

    # 13. TLD popularity
    features["tld_popularity"] = 1 if suffix in POPULAR_TLDS else 0

    # 14. Suspicious file extension
    features["suspicious_file_extension"] = 1 if any(
        parsed.path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS
    ) else 0

    # 15. Domain name length
    features["domain_name_length"] = len(domain)

    # 16. Percentage numeric chars
    features["percentage_numeric_chars"] = (
        features["number_of_digits"] / len(url)
        if len(url) > 0 else 0
    )

    return features

df = pd.read_csv("unram_terbaru_legitphish.csv")

feature_rows = []
for u in df["url"]:
    feature_rows.append(extract_features(u))

df_features = pd.DataFrame(feature_rows)
df_final = pd.concat([df_features, df["label"]], axis=1)

df_final.to_csv("dataset_kampus_legitphish_style.csv", index=False)