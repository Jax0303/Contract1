from sqlalchemy.orm import Session
from schemas import UserCreate  # schemas에서 가져옴

def get_user_by_username(db: Session, username: str):
    from models import User  # 'User' 모델을 함수 내부에서 가져옴
    return db.query(User).filter(User.username == username).first()

def create_user(db: Session, user: UserCreate):
    from models import User  # 'User' 모델을 함수 내부에서 가져옴
    db_user = User(username=user.username, password=user.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
