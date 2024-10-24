import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, MetaData
from sqlalchemy.orm import sessionmaker, declarative_base

# NHN 클라우드 PostgreSQL 연결 정보
DATABASE_URL = "postgresql://ugh:17171717@2613658e-0419-46a7-8bcb-7c51aa595524.external.kr1.postgres.rds.nhncloudservice.com:15432/PostgreRDS"

# SQLAlchemy 엔진 및 세션 설정
engine = create_engine(DATABASE_URL, connect_args={"sslmode": "disable"})

# 세션 로컬 생성
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 베이스 및 메타데이터 정의
Base = declarative_base()
metadata = MetaData()

# 계약서 테이블 ORM 스타일로 정의
class Contract(Base):
    __tablename__ = 'contracts'

    id = Column(Integer, primary_key=True, index=True)
    pds_id = Column(String(8), unique=True, index=True)  # PDS ID
    streamer_id = Column(String)
    game_id = Column(String)
    min_broadcast_length = Column(Integer)
    max_broadcast_length = Column(Integer)
    isfree = Column(Boolean)

# 게임 가이드라인 테이블 ORM 스타일로 정의
class GameGuideline(Base):
    __tablename__ = 'game_guidelines'

    game_id = Column(String, primary_key=True, index=True)
    guideline = Column(String, nullable=False)

# 테이블 생성
Base.metadata.create_all(bind=engine)

# 데이터베이스 세션을 제공하는 함수
def get_db():
    """
    데이터베이스 세션을 제공하는 함수
    FastAPI 의존성 주입을 위해 사용
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
