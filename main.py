from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, field_validator
from typing import List
from fastapi.security import OAuth2PasswordBearer
import logging
from jose import JWTError, jwt
import openai
import time

# OpenAI API 키 설정 (AI 기반 스포일러 탐지를 위해 필요)
openai.api_key = "YOUR_OPENAI_API_KEY"

# JWT 설정(사용자 인증을 위해 필요)
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI 앱 생성
app = FastAPI()

# 로깅 설정(처리 결과 및 속도 표시)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 계약서의 기본 구조 정의
class Contract(BaseModel):
    최소_방송_길이: int
    최대_방송_길이: int
    금지_키워드: List[str]
    스포일러_금지: bool
    수익화_허용: bool
    BGM_사용_금지: bool
    폭력적_콘텐츠_금지: bool

# 방송 정보 정의
class BroadcastCheck(BaseModel):
    방송ID: str
    방송플랫폼: str
    게임ID: str

    # Pydantic V2 스타일로 유효성 검사
    @field_validator("방송ID", "게임ID")
    def validate_ids(cls, value, field):
        if not value.isalnum():
            raise ValueError(f'{field.name}는 영숫자로만 구성되어야 합니다.')
        return value

# JWT 검증 함수 (토큰 만료 처리 포함)
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("exp") < time.time():
            raise HTTPException(status_code=401, detail="토큰이 만료되었습니다.")
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# AI 및 키워드 기반 방송 내용 분석 함수
def analyze_broadcast(broadcast_content: str, contract_conditions: dict, keywords: List[str]):
    """
    방송 내용을 분석하여 금지된 키워드나 스포일러 여부를 탐지.
    AI 기반 분석과 키워드 탐지를 모두 처리.
    """
    # AI 기반 스포일러 탐지
    prompt = f"""
    방송 내용이 아래의 계약 조건을 위반했는지 분석해 주세요.
    계약서 조건: {contract_conditions}
    방송 내용: {broadcast_content}
    금지된 키워드, 스포일러, 수익화 여부 등을 분석해 주세요.
    """
    logging.info("AI 기반으로 방송 내용을 분석 중입니다.")
    ai_response = openai.Completion.create(
        engine="gpt-4",
        prompt=prompt,
        max_tokens=500
    )
    ai_analysis = ai_response.choices[0].text

    # 금지된 키워드 탐지
    keyword_violations = [kw for kw in keywords if kw in broadcast_content]

    return {"AI 분석 결과": ai_analysis, "금지된 키워드 위반": keyword_violations}

# 방송 길이 검사 함수
def check_broadcast_length(메타정보: dict, 계약서: Contract):
    if 메타정보["영상길이"] < 계약서.최소_방송_길이:
        logging.warning(f"방송 {메타정보['방송ID']}: 최소 방송 길이보다 짧음.")
        return f"위반: 최소 방송 길이 {계약서.최소_방송_길이}분보다 짧음."
    if 메타정보["영상길이"] > 계약서.최대_방송_길이:
        logging.warning(f"방송 {메타정보['방송ID']}: 최대 방송 길이를 초과함.")
        return f"위반: 최대 방송 길이 {계약서.최대_방송_길이}분보다 김."
    return None

# 계약서 조건을 불러오는 함수 (예시로 하드코딩된 계약서 조건)
def get_game_contract(게임ID: str) -> Contract:
    logging.info(f"게임 {게임ID}에 대한 계약 조건을 불러오는 중입니다.")
    return Contract(
        최소_방송_길이=60,
        최대_방송_길이=180,
        금지_키워드=["폭력", "음란", "스포일러"],
        스포일러_금지=True,
        수익화_허용=False,
        BGM_사용_금지=True,
        폭력적_콘텐츠_금지=True
    )

# 방송 검사 API 경로
@app.post("/check_contract")
def check_contract(broadcast: BroadcastCheck, token: str = Depends(verify_token)):
    start_time = time.time()
    logging.info(f"방송 {broadcast.방송ID}에 대한 전체 계약 조건을 확인 중입니다.")
    violations = []

    # 게임별 계약 조건 불러오기
    계약서 = get_game_contract(broadcast.게임ID)

    # 방송 길이 검사
    메타정보 = {"영상길이": 120}  # 예시로 방송 길이 120분으로 설정
    길이_위반 = check_broadcast_length(메타정보, 계약서)
    if 길이_위반:
        violations.append(길이_위반)

    # 방송 내용 검사 (모듈화된 AI 및 키워드 기반 분석)
    방송내용 = "이 방송에서는 스포일러와 수익화 내용이 포함되었습니다."
    analysis_results = analyze_broadcast(방송내용, 계약서.dict(), 계약서.금지_키워드)

    # 스포일러 위반 여부 확인
    if 계약서.스포일러_금지 and analysis_results["금지된 키워드 위반"]:
        violations.append("위반: 스포일러 또는 금지된 키워드 포함")

    # 처리 시간 계산 및 로그 기록
    end_time = time.time()
    processing_time = end_time - start_time
    logging.info(f"계약 조건 확인 완료. 처리 시간: {processing_time} 초")

    # 위반 사항 반환
    if violations:
        return {"결과": violations, "AI 분석 결과": analysis_results["AI 분석 결과"]}
    else:
        return {"결과": "위반 사항 없음", "AI 분석 결과": analysis_results["AI 분석 결과"]}
