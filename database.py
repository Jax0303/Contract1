from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "postgresql://ugh:17171717@2613658e-0419-46a7-8bcb-7c51aa595524.external.kr1.postgres.rds.nhncloudservice.com:15432/PostgreRDS"
engine = create_engine(DATABASE_URL, connect_args={"sslmode": "disable"})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
