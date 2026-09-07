from fastapi import APIRouter
from pydantic import BaseModel
import re


router = APIRouter(
    prefix="/detect",
    tags=["Log Threat Analyzer"]
)


class LogRequest(BaseModel):
    log: str


def analyze_log(log):

    log_lower = log.lower()

    risk_score = 0
    threats = []

    # Failed login detection
    failed_login_patterns = [
        "failed login",
        "login failed",
        "authentication failed",
        "invalid password",
        "invalid credentials"
    ]

    if any(pattern in log_lower for pattern in failed_login_patterns):
        risk_score += 30
        threats.append("Failed authentication attempt detected")

    # Brute-force detection
    if (
        "failed login" in log_lower
        or "login failed" in log_lower
    ):
        numbers = re.findall(r"\d+", log_lower)

        if numbers:
            for number in numbers:
                if int(number) >= 5:
                    risk_score += 30
                    threats.append(
                        "Possible brute-force activity detected"
                    )
                    break

    # Privilege escalation
    privilege_patterns = [
        "sudo",
        "root access",
        "privilege escalation",
        "administrator access"
    ]

    if any(pattern in log_lower for pattern in privilege_patterns):
        risk_score += 25
        threats.append(
            "Possible privilege escalation detected"
        )

    # Malware indicators
    malware_patterns = [
        "malware",
        "virus detected",
        "trojan",
        "ransomware",
        "malicious file"
    ]

    if any(pattern in log_lower for pattern in malware_patterns):
        risk_score += 40
        threats.append(
            "Possible malware activity detected"
        )

    # Suspicious network activity
    network_patterns = [
        "port scan",
        "scan detected",
        "multiple connection attempts",
        "suspicious connection",
        "unusual network activity"
    ]

    if any(pattern in log_lower for pattern in network_patterns):
        risk_score += 30
        threats.append(
            "Suspicious network activity detected"
        )

    # SQL injection indicators
    sql_patterns = [
        "union select",
        "' or '1'='1",
        "drop table",
        "select * from",
        "sql injection"
    ]

    if any(pattern in log_lower for pattern in sql_patterns):
        risk_score += 40
        threats.append(
            "Possible SQL injection indicator detected"
        )

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        result = "HIGH RISK"
    elif risk_score >= 30:
        result = "MEDIUM RISK"
    else:
        result = "LOW RISK"

    return {
        "prediction": result,
        "risk_score": risk_score,
        "threats": threats,
        "log": log
    }


@router.post("/log")
def detect_log_threat(request: LogRequest):

    return analyze_log(request.log)