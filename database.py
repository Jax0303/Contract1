from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# SQLite 데이터베이스 경로 설정
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"  # SQLite 파일로 저장
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

# 세션 생성
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 데이터베이스 세션 디펜던시로 사용되는 함수
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
