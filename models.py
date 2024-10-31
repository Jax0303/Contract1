#models.py
from sqlalchemy import Column, Integer, String, Boolean, JSON, DateTime
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)

class Contract(Base):
    __tablename__ = 'contracts'
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    streamer_id = Column(String, nullable=False)
    game_id = Column(String, nullable=False)
    min_broadcast_length = Column(Integer, nullable=False)
    max_broadcast_length = Column(Integer, nullable=False)
    isfree = Column(Boolean, nullable=False, default=False)
    custom_conditions = Column(JSON, nullable=True)  # 맞춤형 조건을 포함하는 JSON 필드
    streamer_signed = Column(Boolean, default=False)  # 스트리머 서명 여부
    developer_signed = Column(Boolean, default=False)  # 개발사 서명 여부
    status = Column(String, default="in_progress")  # 계약 상태
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now())  # 마지막 업데이트 날짜

class Guideline(Base):
    __tablename__ = 'guidelines'
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String, nullable=False)  # 가이드라인 내용 필드
