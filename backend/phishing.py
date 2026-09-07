from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
import os
import re
from urllib.parse import urlparse


router = APIRouter(
    prefix="/detect",
    tags=["Threat Detection"]
)


# Load trained ML model
MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "ml",
    "phishing_model.pkl"
)

model = joblib.load(MODEL_PATH)


# Request model for URL detection
class URLRequest(BaseModel):
    url: str


def analyze_url(url: str):

    # Add scheme if user doesn't provide one
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    risk_score = 0
    warnings = []

    # 1. Check HTTPS
    if parsed.scheme != "https":
        risk_score += 20
        warnings.append("URL does not use HTTPS")

    # 2. Check URL length
    if len(url) > 75:
        risk_score += 20
        warnings.append("Unusually long URL")

    # 3. Check IP address
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain):
        risk_score += 30
        warnings.append("URL uses an IP address instead of a domain")

    # 4. Check @ symbol
    if "@" in url:
        risk_score += 20
        warnings.append("URL contains @ symbol")

    # 5. Check suspicious words
    suspicious_words = [
        "login",
        "verify",
        "account",
        "update",
        "secure",
        "bank",
        "password",
        "signin",
        "confirm"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        risk_score += 20
        warnings.append(
            "Suspicious words found: " + ", ".join(found_words)
        )

    # 6. Check excessive subdomains
    subdomain_count = max(0, len(domain.split(".")) - 2)

    if subdomain_count > 2:
        risk_score += 20
        warnings.append("Too many subdomains")

    # 7. Check hyphen in domain
    if "-" in domain:
        risk_score += 10
        warnings.append("Domain contains hyphen")

    risk_score = min(risk_score, 100)

    # Classification
    if risk_score >= 60:
        result = "PHISHING"
    elif risk_score >= 30:
        result = "SUSPICIOUS"
    else:
        result = "SAFE"

    return {
        "url": url,
        "prediction": result,
        "risk_score": risk_score,
        "warnings": warnings
    }


# URL-based phishing detection
@router.post("/phishing-url")
def detect_phishing_url(request: URLRequest):

    if not request.url.strip():
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty"
        )

    return analyze_url(request.url)


# Original ML endpoint
class PhishingRequest(BaseModel):
    features: list[int]


@router.post("/phishing")
def detect_phishing(request: PhishingRequest):

    if len(request.features) != 30:
        raise HTTPException(
            status_code=400,
            detail="Exactly 30 features are required"
        )

    data = pd.DataFrame(
        [request.features]
    )

    prediction = model.predict(data)[0]

    probabilities = model.predict_proba(data)[0]

    confidence = max(probabilities) * 100

    if prediction == 1:
        result = "LEGITIMATE"
        risk_score = 100 - confidence
    else:
        result = "PHISHING"
        risk_score = confidence

    return {
        "prediction": result,
        "confidence": round(confidence, 2),
        "risk_score": round(risk_score, 2)
    }