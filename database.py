from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base,sessionmaker


DATABASE_URL = "postgresql://myuser:mypassword@localhost/mydatabase"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# 데이터베이스 세션을 생성하는 함수
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
