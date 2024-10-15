from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import List
from fastapi.security import OAuth2PasswordBearer
import logging
from jose import JWTError, jwt
import openai

# OpenAI API 키 설정 (AI 기반 분석을 위해 필요)
openai.api_key = "YOUR_OPENAI_API_KEY"

# JWT 설정
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI 앱 생성
app = FastAPI()

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# 계약서의 기본 구조를 정의하는 모델 (최소 방송 길이 추가)
class Contract(BaseModel):
    최소_방송_길이: int
    최대_방송_길이: int
    금지_키워드: List[str]
    스포일러_금지: bool
    수익화_허용: bool
    BGM_사용_금지: bool
    폭력적_콘텐츠_금지: bool


# 방송 정보를 정의하는 모델
class BroadcastCheck(BaseModel):
    방송ID: str
    방송플랫폼: str


# 하드코딩된 계약 조건 (최소 방송 길이 조건 포함)
계약서 = Contract(
    최소_방송_길이=60,  # 최소 1시간 방송 허용
    최대_방송_길이=180,  # 최대 3시간 방송 허용
    금지_키워드=["폭력", "음란", "스포일러"],
    스포일러_금지=True,
    수익화_허용=False,
    BGM_사용_금지=True,
    폭력적_콘텐츠_금지=True
)


# JWT 검증 함수
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# 스포일러 경고 누락 검사 함수
def no_spoiler_warning_present(방송내용: str):
    # 스포일러라는 단어가 방송 내용에 포함되어 있고, '경고'라는 단어가 없으면 경고 누락으로 판단
    if "스포일러" in 방송내용 and "경고" not in 방송내용:
        return True
    return False


# 스포일러 검사를 위한 함수 (텍스트 내에서 금지된 키워드가 있는지 검사)
def check_text_for_keywords(text: str, keywords: List[str]) -> bool:
    return any(keyword in text for keyword in keywords)


# 방송 메타데이터 추출 (모의 함수 - 실제로는 플랫폼 API에서 데이터를 받아와야 함)
def extract_metadata(방송플랫폼: str, 방송ID: str):
    logging.info(f"방송 {방송ID}의 메타데이터를 추출 중입니다.")
    return {
        "방송ID": 방송ID,
        "방송플랫폼": 방송플랫폼,
        "방송제목": "영화 결말 포함 방송",
        "영상길이": 50  # 예시: 50분 방송
    }


# 방송 내용 분석 (실제 자막 데이터 또는 음성 데이터를 이용)
def analyze_broadcast_content_using_subtitles(broadcast_id: str):
    logging.info(f"방송 {broadcast_id}의 자막을 분석 중입니다.")
    subtitle_content = "이 방송에서는 결말과 스포일러가 포함되었습니다. 수익화와 광고도 있습니다."
    return subtitle_content


# AI 기반 스포일러 탐지 (GPT 활용)
def ai_spoiler_detection(broadcast_content: str, contract_conditions: dict):
    prompt = f"""
    다음 방송 내용이 계약서 조건을 위반했는지 분석해주세요.
    계약서 조건: {contract_conditions}
    방송 내용: {broadcast_content}
    금지된 키워드, 스포일러, 수익화 여부를 분석하세요.
    """
    logging.info("AI 기반으로 스포일러 및 위반 사항을 검사 중입니다.")
    response = openai.Completion.create(
        engine="gpt-4",
        prompt=prompt,
        max_tokens=500
    )
    return response.choices[0].text


# 방송 길이 검사 함수 (최소/최대 조건 포함)
def check_broadcast_length(메타정보: dict, 계약서: Contract):
    # 최소 방송 길이 검사
    if 메타정보["영상길이"] < 계약서.최소_방송_길이:
        logging.warning(f"방송 {메타정보['방송ID']}: 최소 방송 길이보다 짧음.")
        return f"위반: 최소 방송 길이 {계약서.최소_방송_길이}분보다 짧음."

    # 최대 방송 길이 검사
    if 메타정보["영상길이"] > 계약서.최대_방송_길이:
        logging.warning(f"방송 {메타정보['방송ID']}: 허용된 방송 길이를 초과함.")
        return f"위반: 최대 방송 길이 {계약서.최대_방송_길이}분보다 김."

    return None


# 방송 검사 API 경로 (JWT 인증 필요)
@app.post("/check_spoiler")
def check_spoiler(broadcast: BroadcastCheck, token: str = Depends(verify_token)):
    logging.info(f"방송 {broadcast.방송ID}에 대해 스포일러 검사를 시작합니다.")
    방송내용 = analyze_broadcast_content_using_subtitles(broadcast.방송ID)
    # AI 기반 스포일러 및 위반 사항 분석
    ai_analysis = ai_spoiler_detection(방송내용, 계약서.dict())

    if 계약서.스포일러_금지 and check_text_for_keywords(방송내용, ["스포일러", "결말", "Spoiler"]):
        if no_spoiler_warning_present(방송내용):
            logging.warning(f"방송 {broadcast.방송ID}: 스포일러 경고가 누락되었습니다.")
            return {"결과": "위반: 스포일러 경고 누락", "AI 분석 결과": ai_analysis}
    logging.info(f"방송 {broadcast.방송ID}: 스포일러 위반 사항 없음.")
    return {"결과": "위반 사항 없음", "AI 분석 결과": ai_analysis}


# 방송 길이 검사 API 경로 (최소/최대 조건 포함)
@app.post("/check_broadcast_length")
def check_broadcast_length_api(broadcast: BroadcastCheck, token: str = Depends(verify_token)):
    logging.info(f"방송 {broadcast.방송ID}의 길이 조건을 확인 중입니다.")
    메타정보 = extract_metadata(broadcast.방송플랫폼, broadcast.방송ID)

    # 방송 길이 검사
    길이_위반 = check_broadcast_length(메타정보, 계약서)
    if 길이_위반:
        return {"결과": 길이_위반}

    return {"결과": "위반 사항 없음"}


# API 경로: 계약서 전체 검사
@app.post("/check_contract")
def check_contract(broadcast: BroadcastCheck, token: str = Depends(verify_token)):
    logging.info(f"방송 {broadcast.방송ID}에 대해 전체 계약 조건을 확인 중입니다.")
    violations = []

    # 방송 길이 검사
    메타정보 = extract_metadata(broadcast.방송플랫폼, broadcast.방송ID)
    길이_위반 = check_broadcast_length(메타정보, 계약서)
    if 길이_위반:
        violations.append(길이_위반)

    # 방송 내용 검사
    방송내용 = analyze_broadcast_content_using_subtitles(broadcast.방송ID)

    # 스포일러 검사
    if 계약서.스포일러_금지 and check_text_for_keywords(방송내용, ["스포일러", "결말", "Spoiler"]):
        if no_spoiler_warning_present(방송내용):
            violations.append("위반: 스포일러 경고 누락")

    # AI 기반 분석
    ai_analysis = ai_spoiler_detection(방송내용, 계약서.dict())

    if violations:
        return {"결과": violations, "AI 분석 결과": ai_analysis}
    else:
        return {"결과": "위반 사항 없음", "AI 분석 결과": ai_analysis}