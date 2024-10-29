from sqlalchemy import Column, Integer, String, Boolean, JSON
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
    streamer_id = Column(String, nullable=False)
    game_id = Column(String, nullable=False)
    min_broadcast_length = Column(Integer, nullable=False)
    max_broadcast_length = Column(Integer, nullable=False)
    isfree = Column(Boolean, nullable=False, default=False)
    free_conditions = Column(JSON, nullable=True)
    banned_keywords = Column(JSON, nullable=False)
    no_spoilers = Column(Boolean, nullable=False)
    monetization_allowed = Column(Boolean, nullable=False)
    no_bgm_usage = Column(Boolean, nullable=False)
    no_violent_content = Column(Boolean, nullable=False)

class Guideline(Base):
    __tablename__ = 'guidelines'
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String, nullable=False)
