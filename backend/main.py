from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import engine, Base, SessionLocal
from models import User, ScanHistory
from auth import router as auth_router
from security import get_current_user
from phishing import router as phishing_router
from network_ids_api import router as network_ids_router
from log_analyzer import router as log_analyzer_router
from risk_engine import router as risk_engine_router


app = FastAPI(
    title="CyberShield AI",
    description="Multi-Threat Detection Platform",
    version="1.0.0"
)


# ================= CORS =================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ================= DATABASE =================

Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ================= AUTHENTICATION =================

app.include_router(auth_router)


# ================= PHISHING DETECTION =================

app.include_router(phishing_router)


# ================= NETWORK INTRUSION DETECTION =================

app.include_router(network_ids_router)


# ================= LOG THREAT ANALYZER =================

app.include_router(log_analyzer_router)


# ================= AI RISK ENGINE =================

app.include_router(risk_engine_router)


# ================= HOME =================

@app.get("/")
def home():
    return {
        "message": "Welcome to CyberShield AI",
        "status": "Backend is running",
        "database": "Connected"
    }


# ================= PROTECTED ENDPOINT =================

@app.get("/protected")
def protected_route(
    current_user: str = Depends(get_current_user)
):
    return {
        "message": "You have access to the protected area",
        "username": current_user
    }


# ================= SAVE SCAN =================

@app.post("/scan-history")
def save_scan(
    url: str,
    prediction: str,
    risk_score: float,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    scan = ScanHistory(
        username=current_user,
        url=url,
        prediction=prediction,
        risk_score=risk_score
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return {
        "message": "Scan saved successfully",
        "id": scan.id,
        "username": scan.username,
        "url": scan.url,
        "prediction": scan.prediction,
        "risk_score": scan.risk_score
    }


# ================= GET SCAN HISTORY =================

@app.get("/scan-history")
def get_scan_history(
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    scans = (
        db.query(ScanHistory)
        .filter(ScanHistory.username == current_user)
        .order_by(ScanHistory.scanned_at.desc())
        .all()
    )

    return [
        {
            "id": scan.id,
            "url": scan.url,
            "prediction": scan.prediction,
            "risk_score": scan.risk_score,
            "scanned_at": scan.scanned_at
        }
        for scan in scans
    ]