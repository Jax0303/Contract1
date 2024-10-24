from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uuid
import os, json

# FastAPI 앱 생성
app = FastAPI()

# 데이터 모델 정의
class PDSData(BaseModel):
    broadcast_id: str
    violations: list
    ai_analysis: str
    processing_time: float
##
# 데이터를 로컬에 저장하는 API
@app.post("/api/v1/store")
async def store_data(data: PDSData):
    try:
        # 고유 ID 생성 (UUID 사용)
        data_id = str(uuid.uuid4())

        # 로컬 저장 경로 설정
        save_dir = "pds_data"
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        # 데이터를 JSON 파일로 저장
        file_path = os.path.join(save_dir, f"{data_id}.json")
        with open(file_path, "w") as f:
            f.write(json.dumps(data.dict(), indent=4))

        return {"id": data_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail="데이터 저장 중 오류 발생")
