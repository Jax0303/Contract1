from sqlalchemy import Column, Integer, String, Boolean, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# 계약서 테이블 ORM 모델 정의
class Contract(Base):
    __tablename__ = "contracts"

    id = Column(Integer, primary_key=True, index=True)
    streamer_id = Column(String, nullable=False)  # 스트리머 ID
    game_id = Column(String, nullable=False)      # 게임 ID
    min_broadcast_length = Column(Integer, nullable=False)  # 최소 방송 길이
    max_broadcast_length = Column(Integer, nullable=False)  # 최대 방송 길이
    isfree = Column(Boolean, nullable=False, default=False)  # 무료 여부
    free_conditions = Column(JSON, nullable=True)  # 무료 조건을 JSON으로 저장
    banned_keywords = Column(JSON, nullable=False)  # 금지된 키워드 목록 (JSON)
    no_spoilers = Column(Boolean, nullable=False)  # 스포일러 금지 여부
    monetization_allowed = Column(Boolean, nullable=False)  # 수익화 가능 여부
    no_bgm_usage = Column(Boolean, nullable=False)  # BGM 사용 금지 여부
    no_violent_content = Column(Boolean, nullable=False)  # 폭력적 콘텐츠 금지 여부


# 게임 가이드라인 모델 정의
class GameGuideline(Base):
    __tablename__ = 'game_guidelines'

    game_id = Column(String, primary_key=True, index=True)
    guideline = Column(String, nullable=False)
