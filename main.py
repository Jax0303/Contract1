from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import List
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import logging
import secrets
from jose import JWTError, jwt
import requests
import crud, schemas
from datetime import timedelta, datetime
from database import get_db
from auth import get_current_user, authenticate_user
from models import Base
from database import engine
from contextlib import asynccontextmanager

# JWT 설정
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI 앱 생성
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 앱 시작 시 테이블을 생성
    create_tables()
    yield

app = FastAPI(lifespan=lifespan)

# 테이블을 생성하는 함수
def create_tables():
    Base.metadata.create_all(bind=engine)

# PDS 저장소
pds_storage = {}

# JWT 토큰 생성 함수
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta if expires_delta else datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# PDS 요청 처리 함수
def pds_request(method, url, data=None):
    try:
        if method == "POST":
            response = requests.post(url, json=data)
        elif method == "GET":
            response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"PDS 요청 실패: {e}")
        raise HTTPException(status_code=500, detail="PDS 요청 실패")

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

# DSL 계약서 모델 정의
class DSLContract(BaseModel):
    streamer_id: str
    game_id: str
    최소_방송_길이: int
    최대_방송_길이: int
    isfree: bool
    금지_키워드: List[str]
    스포일러_금지: bool
    수익화_허용: bool
    BGM_사용_금지: bool
    폭력적_콘텐츠_금지: bool

# 8자리 고유 PDS ID 생성 함수
def generate_pds_id():
    return secrets.token_hex(4)  # 8자리 고유 ID 생성 (4 bytes = 8 hex digits)

# 계약서 저장 API
@app.post("/contract/save")
def save_contract(contract: DSLContract):
    # 고유 PDS ID 생성
    pds_id = generate_pds_id()

    # 계약서를 로컬 메모리(PDS 저장소)에 저장
    pds_storage[pds_id] = contract.dict()

    return {"message": "Contract saved successfully", "pds_id": pds_id}

# 계약서 불러오기 API (PDS ID로 계약서 조회)
@app.get("/contract/{pds_id}")
def get_contract(pds_id: str):
    # PDS 저장소에서 계약서 불러오기
    contract = pds_storage.get(pds_id)

    if not contract:
        raise HTTPException(status_code=404, detail="해당 PDS ID에 대한 계약서를 찾을 수 없습니다.")

    # 계약서 내용과 PDS ID 함께 반환
    return {
        "pds_id": pds_id,
        "contract_details": contract  # 계약서 전체 내용 반환
    }

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
    if 메타정보["영상길이"] < 계약서["최소_방송_길이"]:
        return f"위반: 최소 방송 길이 {계약서['최소_방송_길이']}분보다 짧음."
    if 메타정보["영상길이"] > 계약서["최대_방송_길이"]:
        return f"위반: 최대 방송 길이 {계약서['최대_방송_길이']}분보다 김."
    return None

# 금지된 키워드 검사 함수
def check_text_for_keywords(text, keywords):
    return any(keyword in text for keyword in keywords)

# 위반 사항 검사 함수
def check_violations(contract, broadcast_data):
    violations = []
    violation = check_broadcast_length(broadcast_data, contract)
    if violation:
        violations.append(violation)

    if check_text_for_keywords(broadcast_data["방송제목"], contract["금지_키워드"]):
        violations.append("위반: 금지된 키워드가 제목에 포함됨.")

    방송내용 = "이 방송에서는 수익화와 스포일러가 포함되었습니다."
    if check_text_for_keywords(방송내용, ["수익화", "광고", "Advertisment"]):
        violations.append("위반: 수익 창출 금지 위반")

    if check_text_for_keywords(방송내용, ["스포일러", "결말", "Spoiler"]) and contract["스포일러_금지"]:
        violations.append("위반: 스포일러 송출 금지")

    if check_text_for_keywords(방송내용, ["BGM", "사운드트랙", "음악"]):
        violations.append("위반: BGM 사용 금지")

    return violations

# 계약서 조건을 체크하는 API
@app.post("/check_contract")
def check_contract(broadcast: BroadcastCheck, token: str = Depends(oauth2_scheme)):
    pds_id = broadcast.게임ID  # PDS ID를 사용해 계약서 찾기

    contract = pds_storage.get(pds_id)

    if not contract:
        raise HTTPException(status_code=404, detail="해당 PDS ID에 대한 계약서를 찾을 수 없습니다.")

    # 메타데이터 추출
    메타정보 = extract_metadata(broadcast.방송플랫폼, broadcast.방송ID)

    # 위반 사항 검사
    violations = check_violations(contract, 메타정보)

    if violations:
        # OBS 회사에 위반 사항 알림 (예시)
        return {"message": "Contract violated", "violations": violations}

    return {"message": "No contract violations"}
