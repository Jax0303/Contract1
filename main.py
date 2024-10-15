from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, field_validator
from typing import List
from fastapi.security import OAuth2PasswordBearer
import logging
from jose import JWTError, jwt
import openai
import requests
from functools import lru_cache
import time

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

# 계약서의 기본 구조 정의
class Contract(BaseModel):
    최소_방송_길이: int
    최대_방송_길이: int
    금지_키워드: List[str]
    스포일러_금지: bool
    수익화_허용: bool
    BGM_사용_금지: bool
    폭력적_콘텐츠_금지: bool
    수익_분배율: float  # 수익 분배 비율
    허용_플랫폼: List[str]  # 허용된 스트리밍 플랫폼 리스트

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

# 캐싱을 사용하여 API 호출 성능 최적화
@lru_cache(maxsize=100)
def get_game_contract(게임ID: str) -> Contract:
    logging.info(f"게임 {게임ID}에 대한 계약 조건을 불러오는 중입니다.")
    try:
        response = requests.get(f"http://api.server.address/monitized?game-id={게임ID}")
        response.raise_for_status()  # HTTP 에러 발생 시 예외를 발생시킴
    except requests.exceptions.HTTPError as errh:
        raise HTTPException(status_code=500, detail=f"HTTP 에러 발생: {errh}")
    except requests.exceptions.ConnectionError as errc:
        raise HTTPException(status_code=500, detail=f"연결 오류: {errc}")
    except requests.exceptions.Timeout as errt:
        raise HTTPException(status_code=500, detail=f"요청 시간 초과: {errt}")
    except requests.exceptions.RequestException as err:
        raise HTTPException(status_code=500, detail=f"요청 오류: {err}")

    data = response.json()
    return Contract(
        최소_방송_길이=60,
        최대_방송_길이=180,
        금지_키워드=["폭력", "음란", "스포일러"],
        스포일러_금지=True,
        수익화_허용=data['isFree'],
        BGM_사용_금지=True,
        폭력적_콘텐츠_금지=True,
        수익_분배율=0.3,
        허용_플랫폼=["YouTube", "Twitch"]
    )

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

# 스포일러 및 금지된 키워드 탐지 함수
def check_text_for_keywords(text: str, keywords: List[str]) -> bool:
    return any(keyword in text for keyword in keywords)

# 방송 메타데이터 추출 (스트리머 정보 반영)
def extract_metadata(방송플랫폼: str, 방송ID: str):
    logging.info(f"방송 {방송ID}의 메타데이터를 추출 중입니다.")
    streamer_data = {
        "옥냥이": {
            "스트리밍링크": "https://example.com/stream",
            "평균조회수": "20만"
        }
    }
    return {
        "방송ID": 방송ID,
        "방송플랫폼": 방송플랫폼,
        "방송제목": "영화 결말 포함 방송",
        "영상길이": 120,
        "스트리머정보": streamer_data.get("옥냥이")
    }

# AI 기반 스포일러 탐지 함수
def ai_spoiler_detection(broadcast_content: str, contract_conditions: dict):
    prompt = f"""
    방송 내용이 아래의 계약 조건을 위반했는지 분석해 주세요.
    계약서 조건: {contract_conditions}
    방송 내용: {broadcast_content}
    금지된 키워드, 스포일러, 수익화 여부 등을 분석해 주세요.
    """
    logging.info("AI 기반으로 방송 내용을 분석 중입니다.")
    response = openai.Completion.create(
        engine="gpt-4",
        prompt=prompt,
        max_tokens=500
    )
    return response.choices[0].text

# DAO 기반 계약 투표
def dao_vote(contract_id: str, proposal: str):
    logging.info(f"DAO 투표가 시작되었습니다. 제안: {proposal}")
    try:
        vote_result = requests.post(f"http://dao.server/vote/{contract_id}", json={"proposal": proposal})
        vote_result.raise_for_status()  # 요청 성공 여부 확인
        logging.info(f"DAO 투표 결과: {vote_result.json()}")
        return vote_result.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"DAO 투표 요청 실패: {e}")
        return {"error": "DAO 투표 실패"}

# IPFS에 계약 데이터 저장
def store_data_on_ipfs(data: dict):
    try:
        ipfs_response = requests.post("http://ipfs.server/api/store", json=data)
        ipfs_response.raise_for_status()
        ipfs_hash = ipfs_response.json()["hash"]
        logging.info(f"데이터가 IPFS에 저장되었습니다. 해시: {ipfs_hash}")
        return ipfs_hash
    except requests.exceptions.RequestException as e:
        logging.error(f"IPFS 저장 실패: {e}")
        return {"error": "IPFS 저장 실패"}

# 블록체인 기반 수익 분배
def distribute_revenue_on_blockchain(revenue: float, contract: Contract):
    try:
        response = requests.post("http://blockchain.server/api/distribute",
                                 json={"revenue": revenue, "contract": contract.dict()})
        response.raise_for_status()
        logging.info(f"수익이 블록체인을 통해 성공적으로 분배되었습니다. 결과: {response.json()}")
    except requests.exceptions.RequestException as e:
        logging.error(f"블록체인 수익 분배 실패: {e}")

# 스마트 계약 실행
def execute_smart_contract(contract_data: dict):
    try:
        response = requests.post("http://blockchain.server/api/execute", json=contract_data)
        response.raise_for_status()
        logging.info(f"스마트 계약이 성공적으로 실행되었습니다. 결과: {response.json()}")
    except requests.exceptions.RequestException as e:
        logging.error(f"스마트 계약 실행 실패: {e}")

# 실시간 블록체인 모니터링
def real_time_blockchain_monitoring(broadcast_id: str, contract: Contract):
    try:
        response = requests.post(f"http://blockchain.server/api/monitor/{broadcast_id}", json={"contract": contract.dict()})
        response.raise_for_status()
        logging.info(f"실시간 블록체인 모니터링이 성공적으로 시작되었습니다. 결과: {response.json()}")
    except requests.exceptions.RequestException as e:
        logging.error(f"실시간 블록체인 모니터링 실패: {e}")

# 방송 길이 검사 함수
def check_broadcast_length(메타정보: dict, 계약서: Contract):
    if 메타정보["영상길이"] < 계약서.최소_방송_길이:
        logging.warning(f"방송 {메타정보['방송ID']}: 최소 방송 길이보다 짧음.")
        return f"위반: 최소 방송 길이 {계약서.최소_방송_길이}분보다 짧음."
    if 메타정보["영상길이"] > 계약서.최대_방송_길이:
        logging.warning(f"방송 {메타정보['방송ID']}: 최대 방송 길이를 초과함.")
        return f"위반: 최대 방송 길이 {계약서.최대_방송_길이}분보다 김."
    return None

# 방송 검사 API 경로
@app.post("/check_contract")
def check_contract(broadcast: BroadcastCheck, token: str = Depends(verify_token)):
    start_time = time.time()
    logging.info(f"방송 {broadcast.방송ID}에 대한 전체 계약 조건을 확인 중입니다.")
    violations = []

    # 게임별 계약 조건 불러오기
    계약서 = get_game_contract(broadcast.게임ID)

    # 방송 메타데이터 추출
    메타정보 = extract_metadata(broadcast.방송플랫폼, broadcast.방송ID)

    # 방송 길이 검사
    길이_위반 = check_broadcast_length(메타정보, 계약서)
    if 길이_위반:
        violations.append(길이_위반)

    # 방송 내용 검사 (AI 기반 분석)
    방송내용 = "이 방송에서는 스포일러와 수익화 내용이 포함되었습니다."
    ai_analysis = ai_spoiler_detection(방송내용, 계약서.dict())

    if 계약서.스포일러_금지 and check_text_for_keywords(방송내용, 계약서.금지_키워드):
        violations.append("위반: 스포일러 또는 금지된 키워드 포함")

    # 실시간 블록체인 모니터링
    real_time_blockchain_monitoring(broadcast.방송ID, 계약서)

    # DAO 투표 실행 (특정 변경 사항에 대해 투표 진행)
    dao_vote_result = dao_vote(broadcast.게임ID, "계약 조건 변경")

    # 블록체인 기반 수익 분배 처리 (예시로 수익 분배)
    distribute_revenue_on_blockchain(1000.0, 계약서)

    # 스마트 계약 실행 (계약 조건 위반 시 스마트 계약 적용)
    execute_smart_contract(계약서.dict())

    # 처리 시간 계산 및 로그 기록
    end_time = time.time()
    processing_time = end_time - start_time
    logging.info(f"계약 조건 확인 완료. 처리 시간: {processing_time} 초")

    # 위반 사항 반환
    if violations:
        return {"결과": violations, "AI 분석 결과": ai_analysis, "DAO 투표 결과": dao_vote_result}
    else:
        return {"결과": "위반 사항 없음", "AI 분석 결과": ai_analysis, "DAO 투표 결과": dao_vote_result}

