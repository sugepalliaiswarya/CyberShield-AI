import re
from urllib.parse import urlparse


def extract_features(url):
    parsed_url = urlparse(url)

    features = {
        "url_length": len(url),
        "has_https": 1 if parsed_url.scheme == "https" else 0,
        "has_ip_address": 1 if re.match(
            r"^https?://(\d{1,3}\.){3}\d{1,3}", url
        ) else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_dash": 1 if "-" in parsed_url.netloc else 0,
        "subdomain_count": len(parsed_url.netloc.split(".")) - 2,
        "has_suspicious_words": 1 if any(
            word in url.lower()
            for word in [
                "login",
                "verify",
                "account",
                "update",
                "secure",
                "bank",
                "password"
            ]
        ) else 0
    }

    return features


def detect_phishing(url):
    features = extract_features(url)

    risk_score = 0

    if features["url_length"] > 75:
        risk_score += 20

    if features["has_https"] == 0:
        risk_score += 20

    if features["has_ip_address"] == 1:
        risk_score += 30

    if features["has_at_symbol"] == 1:
        risk_score += 20

    if features["has_dash"] == 1:
        risk_score += 10

    if features["subdomain_count"] > 2:
        risk_score += 20

    if features["has_suspicious_words"] == 1:
        risk_score += 20

    if risk_score >= 60:
        result = "PHISHING"
    elif risk_score >= 30:
        result = "SUSPICIOUS"
    else:
        result = "SAFE"

    return {
        "url": url,
        "risk_score": min(risk_score, 100),
        "result": result,
        "features": features
    }


if __name__ == "__main__":
    test_url = "http://example.com/login"

    result = detect_phishing(test_url)

    print(result)