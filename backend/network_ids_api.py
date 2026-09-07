from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import pandas as pd
import joblib
import os


router = APIRouter(
    prefix="/detect",
    tags=["Network Intrusion Detection"]
)


MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "ml",
    "network_ids",
    "network_ids_model.pkl"
)


model = joblib.load(MODEL_PATH)


class NetworkRequest(BaseModel):
    packet_count: int
    connection_duration: int
    failed_connections: int
    bytes_sent: int
    bytes_received: int
    suspicious_port: int


@router.post("/network")
def detect_network_intrusion(request: NetworkRequest):

    if request.packet_count < 0:
        raise HTTPException(
            status_code=400,
            detail="Packet count cannot be negative"
        )

    if request.connection_duration < 0:
        raise HTTPException(
            status_code=400,
            detail="Connection duration cannot be negative"
        )

    if request.failed_connections < 0:
        raise HTTPException(
            status_code=400,
            detail="Failed connections cannot be negative"
        )

    if request.bytes_sent < 0 or request.bytes_received < 0:
        raise HTTPException(
            status_code=400,
            detail="Byte values cannot be negative"
        )

    if request.suspicious_port not in [0, 1]:
        raise HTTPException(
            status_code=400,
            detail="suspicious_port must be 0 or 1"
        )

    data = pd.DataFrame([
        {
            "packet_count": request.packet_count,
            "connection_duration": request.connection_duration,
            "failed_connections": request.failed_connections,
            "bytes_sent": request.bytes_sent,
            "bytes_received": request.bytes_received,
            "suspicious_port": request.suspicious_port
        }
    ])

    prediction = model.predict(data)[0]

    probabilities = model.predict_proba(data)[0]

    confidence = max(probabilities) * 100

    if prediction == 1:
        result = "INTRUSION"
        risk_score = confidence
    else:
        result = "NORMAL"
        risk_score = 100 - confidence

    return {
        "prediction": result,
        "confidence": round(confidence, 2),
        "risk_score": round(risk_score, 2),
        "features": {
            "packet_count": request.packet_count,
            "connection_duration": request.connection_duration,
            "failed_connections": request.failed_connections,
            "bytes_sent": request.bytes_sent,
            "bytes_received": request.bytes_received,
            "suspicious_port": request.suspicious_port
        }
    }