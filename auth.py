from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from database import get_db
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

SECRET_KEY = "985c4ec8c68448813ee2b5837904d01a10cc4644337f0f31a88620d3fab471b4" #추후에 환경변수로 관리
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, username: str, password: str):
    from crud import get_user_by_username
    user = get_user_by_username(db, username)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

def create_access_token(data: dict, expires_delta: timedelta = None):
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def create_reset_token(email: str):
    expiration = datetime.utcnow() + timedelta(hours=1)  # 1시간 유효
    to_encode = {"sub": email, "exp": expiration}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
