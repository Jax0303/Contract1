from fastapi import FastAPI, Depends, HTTPException, Form
from pydantic import BaseModel, Field
from typing import List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import logging
from jose import JWTError, jwt
import requests
from datetime import timedelta, datetime

# JWT 설정
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI 앱 생성
app = FastAPI()

# 계약서 저장을 위한 임시 저장소 (게임 ID와 PDS ID 매핑)
contract_storage = {}

# JWT 토큰 생성 함수
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 로그인 경로 - JWT 토큰 발급
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # TODO: 실제 사용자 데이터베이스 인증 구현 필요
    if form_data.username != "user" or form_data.password != "password":
        raise HTTPException(
            status_code=401,
            detail="사용자 이름 또는 비밀번호가 잘못되었습니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# 인증된 사용자만 접근 가능한 API
@app.get("/users/me")
async def read_users_me(username: str = Depends(oauth2_scheme)):
    return {"username": username}

# DSL 계약서 모델 정의
class DSLContract(BaseModel):
    streamer_id: str
    game_id: str
    최소_방송_길이: int
    최대_방송_길이: int
    isfree: bool  # isfree 조건 추가
    금지_키워드: List[str]
    스포일러_금지: bool
    수익화_허용: bool
    BGM_사용_금지: bool
    폭력적_콘텐츠_금지: bool

# PDS에 데이터를 저장하는 함수
def store_contract_on_pds(contract_data: dict):
    """
    계약서를 PDS에 저장하고, 저장된 데이터의 ID를 반환.
    """
    try:
        pds_api_url = "http://localhost:8000/api/v1/store"  # PDS API URL 예시
        response = requests.post(pds_api_url, json=contract_data)
        response.raise_for_status()
        pds_id = response.json()["id"]
        logging.info(f"계약서가 PDS에 저장되었습니다. PDS ID: {pds_id}")
        return pds_id
    except requests.RequestException as e:
        logging.error(f"PDS 저장 실패: {e}")
        raise HTTPException(status_code=500, detail="PDS 저장 실패: 데이터를 저장하지 못했습니다.")

# PDS에서 데이터를 불러오는 함수
def load_contract_from_pds(pds_id: str):
    """
    PDS에서 계약서를 불러오는 함수.
    """
    try:
        pds_api_url = f"http://localhost:8000/api/v1/store/{pds_id}"  # PDS API URL 예시
        response = requests.get(pds_api_url)
        response.raise_for_status()
        contract_data = response.json()
        logging.info(f"PDS에서 계약서 불러오기 성공. PDS ID: {pds_id}")
        return contract_data
    except requests.RequestException as e:
        logging.error(f"PDS 불러오기 실패: {e}")
        raise HTTPException(status_code=500, detail="PDS 불러오기 실패: 데이터를 불러오지 못했습니다.")

# 계약서를 저장하는 API
@app.post("/contract/save")
def save_contract(contract: DSLContract):
    pds_id = store_contract_on_pds(contract.dict())  # 계약서를 PDS에 저장
    if not pds_id:
        raise HTTPException(status_code=500, detail="PDS에 계약서 저장 실패")

    contract_storage[contract.game_id] = pds_id  # 게임 ID와 PDS ID 매핑
    return {"message": "Contract saved successfully", "pds_id": pds_id, "game_id": contract.game_id}

# 게임 ID로 계약서를 불러오는 API
@app.get("/contract/{game_id}")
def get_contract(game_id: str):
    pds_id = contract_storage.get(game_id)
    if not pds_id:
        raise HTTPException(status_code=404, detail="해당 게임 ID에 대한 계약서를 찾을 수 없습니다.")

    contract = load_contract_from_pds(pds_id)
    if not contract:
        raise HTTPException(status_code=500, detail="PDS에서 계약서 불러오기 실패")

    return contract

# 방송 데이터 모델 정의
class BroadcastCheck(BaseModel):
    방송ID: str = Field(..., alias="broadcast_id")
    방송플랫폼: str = Field(..., alias="broadcast_platform")
    게임ID: str = Field(..., alias="game_id")
    방송내용: str = Field(..., alias="content")

# 방송 메타데이터 추출 함수 (실제 플랫폼 API 연동 필요)
def extract_metadata(방송플랫폼, 방송ID):
    # TODO: 실제 방송 플랫폼 API 연동 필요 (예: YouTube, Twitch)
    return {
        "영상길이": 120,  # 방송 길이 (분 단위 예시)
        "방송제목": "테스트 방송 제목"
    }

# 방송 길이 검사 함수
def check_broadcast_length(메타정보: dict, 계약서: dict):
    if 메타정보["영상길이"] < 계약서["최소_방송_길이"]:
        logging.warning(f"방송 {메타정보['방송ID']}: 최소 방송 길이보다 짧음.")
        return f"위반: 최소 방송 길이 {계약서['최소_방송_길이']}분보다 짧음."
    if 메타정보["영상길이"] > 계약서["최대_방송_길이"]:
        logging.warning(f"방송 {메타정보['방송ID']}: 최대 방송 길이를 초과함.")
        return f"위반: 최대 방송 길이 {계약서['최대_방송_길이']}분보다 김."
    return None

# 금지된 키워드 검사 함수
def check_text_for_keywords(text, keywords):
    return any(keyword in text for keyword in keywords)

# 방송 내용 분석 함수
def analyze_broadcast_content(방송플랫폼, 방송ID):
    # TODO: 실제 방송 내용을 분석하기 위한 로직 추가 필요
    return "이 방송에서는 수익화와 스포일러가 포함되었습니다."

# OBS 담당 회사에 위반 사항을 알리는 함수
def notify_violation(game_id: str, violation_details: dict):
    obs_api_url = "https://obs-company-api.com/violation"  # 예시 URL
    try:
        response = requests.post(obs_api_url, json={
            "game_id": game_id,
            "violations": violation_details
        })
        response.raise_for_status()
        logging.info(f"Violation reported to OBS company for game {game_id}")
    except requests.RequestException as e:
        logging.error(f"OBS 회사에 위반 사항을 알리는 데 실패했습니다: {e}")

# 계약서 조건을 체크하는 API
@app.post("/check_contract")
def check_contract(broadcast: BroadcastCheck, token: str = Depends(oauth2_scheme)):
    logging.info(f"방송 {broadcast.방송ID}에 대한 계약 조건을 확인 중입니다.")
    violations = []

    # PDS에서 계약서 불러오기
    pds_id = contract_storage.get(broadcast.게임ID)
    if not pds_id:
        raise HTTPException(status_code=404, detail="해당 게임 ID에 대한 계약서를 찾을 수 없습니다.")

    contract = load_contract_from_pds(pds_id)
    if not contract:
        raise HTTPException(status_code=500, detail="PDS에서 계약서 불러오기 실패")

    # 1. 방송 메타데이터 추출
    메타정보 = extract_metadata(broadcast.방송플랫폼, broadcast.방송ID)

    # 2. 방송 길이 검사
    길이_위반 = check_broadcast_length(메타정보, contract)
    if 길이_위반:
        violations.append(길이_위반)

    # 3. 방송 제목에 금지된 키워드 검사
    if check_text_for_keywords(메타정보["방송제목"], contract["금지_키워드"]):
        violations.append("위반: 금지된 키워드가 제목에 포함됨.")

    # 4. 방송 내용 분석
    방송내용 = analyze_broadcast_content(broadcast.방송플랫폼, broadcast.방송ID)

    # 5. 수익화 금지 여부 검사
    if check_text_for_keywords(방송내용, ["수익화", "광고", "Advertisment"]):
        violations.append("위반: 수익 창출 금지 위반")

    # 6. 스포일러 송출 금지 여부 검사
    if check_text_for_keywords(방송내용, ["스포일러", "결말", "Spoiler"]) and contract["스포일러_금지"]:
        violations.append("위반: 스포일러 송출 금지")

    # 7. BGM 사용 여부 검사
    if check_text_for_keywords(방송내용, ["BGM", "사운드트랙", "음악"]):
        violations.append("위반: BGM 사용 금지")

    # 위반 사항이 있을 경우 OBS 회사에 알림
    if violations:
        notify_violation(broadcast.게임ID, violations)
        return {"message": "Contract violated", "violations": violations}

    return {"message": "No contract violations"}

