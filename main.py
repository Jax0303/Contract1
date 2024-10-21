import uuid
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import List
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import logging
import secrets
from jose import JWTError, jwt
import requests
from datetime import timedelta, datetime
from database import get_db, engine, metadata, contracts_table
from sqlalchemy import Table, Column, Integer, String, Boolean, inspect
from contextlib import asynccontextmanager
import crud, schemas
from auth import get_current_user, authenticate_user

# JWT 설정
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI 앱 생성
@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    yield

app = FastAPI(lifespan=lifespan)

# 중복되지 않는 8자리 PDS ID를 생성하는 함수
def generate_pds_id():
    return str(uuid.uuid4()).replace('-', '')[:8]

# 중복되지 않는 테이블명을 생성하는 함수 (inspect 사용)
def get_next_table_name(base_name="contract_table"):
    i = 1
    inspector = inspect(engine)  # SQLAlchemy inspector를 사용하여 기존 테이블 목록을 가져옴
    existing_tables = inspector.get_table_names()  # 기존 테이블 목록을 가져옴

    table_name = f"{base_name}_{i}"

    while table_name in existing_tables:
        i += 1
        table_name = f"{base_name}_{i}"

    return table_name

# 새로운 테이블을 생성하는 함수
def create_new_table():
    next_table_name = get_next_table_name()  # 중복되지 않는 새 테이블 이름 생성
    new_table = Table(
        next_table_name,
        metadata,
        Column('id', Integer, primary_key=True),
        Column('streamer_id', String),
        Column('game_id', String),
        Column('min_broadcast_length', Integer),
        Column('max_broadcast_length', Integer),
        Column('isfree', Boolean),
        Column('pds_id', String(8), unique=True, index=True),  # 8자리 PDS ID 추가
    )
    metadata.create_all(bind=engine, tables=[new_table])
    print(f"Table '{next_table_name}' created.")

# 모든 테이블을 생성하는 함수
def create_tables():
    create_new_table()

# JWT 토큰 생성 함수
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 로그인 경로 - JWT 토큰 발급
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="사용자 이름 또는 비밀번호가 잘못되었습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=timedelta(minutes=30)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# 계약서 저장 API (테이블을 동적으로 생성하여 계약서 저장)
@app.post("/contract/save")
def save_contract(contract: schemas.DSLContract, db: Session = Depends(get_db)):
    # PDS ID 생성
    pds_id = generate_pds_id()

    # 계약서 데이터를 외부 PDS(PostgreSQL)로 저장
    new_contract = contracts_table.insert().values(
        pds_id=pds_id,
        streamer_id=contract.streamer_id,
        game_id=contract.game_id,
        min_broadcast_length=contract.min_broadcast_length,
        max_broadcast_length=contract.max_broadcast_length,
        isfree=contract.isfree
    )

    db.execute(new_contract)
    db.commit()

    return {"message": "Contract saved successfully", "pds_id": pds_id}

# PDS ID로 계약서 조회 API
@app.get("/contract/{pds_id}")
def get_contract_by_pds_id(pds_id: str, db: Session = Depends(get_db)):
    query = contracts_table.select().where(contracts_table.c.pds_id == pds_id)
    result = db.execute(query).fetchone()

    if not result:
        raise HTTPException(status_code=404, detail="해당 PDS ID에 대한 계약서를 찾을 수 없습니다.")

    return {
        "streamer_id": result.streamer_id,
        "game_id": result.game_id,
        "min_broadcast_length": result.min_broadcast_length,
        "max_broadcast_length": result.max_broadcast_length,
        "isfree": result.isfree
    }

# 인증된 사용자 정보 조회
@app.get("/users/me", response_model=schemas.UserResponse)
async def read_users_me(current_user: schemas.UserResponse = Depends(get_current_user)):
    return current_user

# 사용자 생성 API
@app.post("/users/", response_model=schemas.UserResponse)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="이미 등록된 사용자 이름입니다.")
    return crud.create_user(db=db, user=user)

# 방송 데이터 모델 정의
class BroadcastCheck(BaseModel):
    방송ID: str = Field(..., alias="broadcast_id")
    방송플랫폼: str = Field(..., alias="broadcast_platform")
    게임ID: str = Field(..., alias="game_id")
    방송내용: str = Field(..., alias="content")

# 방송 메타데이터 추출 함수
def extract_metadata(방송플랫폼, 방송ID):
    return {
        "영상길이": 120,  # 방송 길이 (분 단위 예시)
        "방송제목": "테스트 방송 제목"
    }

# 방송 길이 검사 함수
def check_broadcast_length(메타정보: dict, 계약서: dict):
    if 메타정보["영상길이"] < 계약서["min_broadcast_length"]:
        return f"위반: 최소 방송 길이 {계약서['min_broadcast_length']}분보다 짧음."
    if 메타정보["영상길이"] > 계약서["max_broadcast_length"]:
        return f"위반: 최대 방송 길이 {계약서['max_broadcast_length']}분보다 김."
    return None

# 위반 사항 검사 함수
def check_violations(contract, broadcast_data):
    violations = []
    violation = check_broadcast_length(broadcast_data, contract)
    if violation:
        violations.append(violation)

    return violations

# 계약서 조건을 체크하는 API
@app.post("/check_contract")
def check_contract(broadcast: BroadcastCheck, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    pds_id = broadcast.게임ID  # PDS ID를 사용해 계약서 찾기

    query = contracts_table.select().where(contracts_table.c.pds_id == pds_id)
    result = db.execute(query).fetchone()

    if not result:
        raise HTTPException(status_code=404, detail="해당 PDS ID에 대한 계약서를 찾을 수 없습니다.")

    # 메타데이터 추출
    메타정보 = extract_metadata(broadcast.방송플랫폼, broadcast.방송ID)

    # 위반 사항 검사
    violations = check_violations(result, 메타정보)

    if violations:
        return {"message": "Contract violated", "violations": violations}

    return {"message": "No contract violations"}
