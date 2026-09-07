from sqlalchemy import Column, Integer, String, Float, DateTime
from database import Base
from datetime import datetime


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False)
    url = Column(String, nullable=False)
    prediction = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False)
    scanned_at = Column(DateTime, default=datetime.utcnow)