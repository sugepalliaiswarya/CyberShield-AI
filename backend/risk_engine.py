from fastapi import APIRouter
from pydantic import BaseModel


router = APIRouter(
    prefix="/risk",
    tags=["AI Risk Engine"]
)


class RiskRequest(BaseModel):
    phishing_risk: float
    network_risk: float
    log_risk: float


@router.post("/calculate")
def calculate_risk(request: RiskRequest):

    phishing_risk = max(0, min(request.phishing_risk, 100))
    network_risk = max(0, min(request.network_risk, 100))
    log_risk = max(0, min(request.log_risk, 100))

    overall_risk = (
        phishing_risk * 0.40
        + network_risk * 0.35
        + log_risk * 0.25
    )

    overall_risk = round(overall_risk, 2)

    if overall_risk >= 80:
        risk_level = "CRITICAL"
    elif overall_risk >= 60:
        risk_level = "HIGH"
    elif overall_risk >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "phishing_risk": phishing_risk,
        "network_risk": network_risk,
        "log_risk": log_risk,
        "overall_risk": overall_risk,
        "risk_level": risk_level
    }