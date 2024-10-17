from sqlalchemy.orm import Session
from models import User

# 사용자 조회 함수
def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

# 사용자 생성 함수
def create_user(db: Session, username: str, password: str):
    user = User(username=username)
    user.set_password(password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
