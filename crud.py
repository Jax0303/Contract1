from sqlalchemy.orm import Session
from schemas import UserCreate  # schemas에서 가져옴
from auth import get_password_hash  # 비밀번호 해싱 함수

# 사용자 목록 조회
def get_user_by_username(db: Session, username: str):
    from models import User  # 'User' 모델을 함수 내부에서 가져옴
    return db.query(User).filter(User.username == username).first()

# 사용자 생성
def create_user(db: Session, user: UserCreate):
    from models import User  # 'User' 모델을 함수 내부에서 가져옴
    hashed_password = get_password_hash(user.password)  # 비밀번호 해싱
    db_user = User(username=user.username, hashed_password=hashed_password, email=user.email)  # hashed_password 사용
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
