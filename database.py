import os
from sqlalchemy import create_engine, Table, Column, Integer, String, Boolean, MetaData
from sqlalchemy.orm import sessionmaker, declarative_base

# 데이터베이스 URL 설정 (RDS PostgreSQL)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:17171717@database-1.c3swiii0kpap.eu-north-1.rds.amazonaws.com:5432/mydatabase")

# SQLAlchemy 엔진 및 세션 설정
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 베이스 및 메타데이터 정의
Base = declarative_base()
metadata = MetaData()

# 계약서 테이블 정의
contracts_table = Table(
    'contracts',  # 테이블 이름
    metadata,
    Column('id', Integer, primary_key=True),
    Column('pds_id', String(8), unique=True, index=True),  # PDS ID
    Column('streamer_id', String),
    Column('game_id', String),
    Column('min_broadcast_length', Integer),
    Column('max_broadcast_length', Integer),
    Column('isfree', Boolean)
)

# 테이블 생성
metadata.create_all(bind=engine)

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
