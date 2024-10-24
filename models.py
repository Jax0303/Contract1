from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# 계약서 테이블 ORM 모델 정의
class Contract(Base):
    __tablename__ = "contracts"

    id = Column(Integer, primary_key=True, index=True)
    pds_id = Column(String(8), unique=True, index=True)  # PDS ID
    streamer_id = Column(String)
    game_id = Column(String)
    min_broadcast_length = Column(Integer)
    max_broadcast_length = Column(Integer)
    isfree = Column(Boolean)


# 게임 가이드라인 모델 정의
class GameGuideline(Base):
    __tablename__ = 'game_guidelines'

    game_id = Column(String, primary_key=True, index=True)
    guideline = Column(String, nullable=False)
