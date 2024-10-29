from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import datetime

# 사용자 관련 스키마 정의
class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr

    class Config:
        from_attributes = True  # orm_mode에서 from_attributes로 변경

# 비밀번호 재설정 스키마
class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

# 맞춤형 조건을 정의하는 스키마
class CustomConditions(BaseModel):
    banned_keywords: List[str]
    no_spoilers: bool
    monetization_allowed: bool
    no_bgm_usage: bool
    no_violent_content: bool

# 계약 관련 스키마
class DSLContract(BaseModel):
    title: str
    streamer_id: str
    game_id: str
    min_broadcast_length: int
    max_broadcast_length: int
    isfree: bool  # 수익화 여부를 나타내는 필드
    custom_conditions: Optional[CustomConditions] = None  # 맞춤형 조건을 포함하는 필드, isfree 참일때만
    streamer_signed: bool = False  # 스트리머 서명 여부
    developer_signed: bool = False  # 개발사 서명 여부
    status: str = "in_progress"  # 계약 상태
    last_updated: datetime = None  # 마지막 업데이트 날짜

# 방송 메타데이터 검사 관련 스키마
class BroadcastCheck(BaseModel):
    broadcast_id: str = Field(..., alias="방송ID")
    broadcast_platform: str = Field(..., alias="방송플랫폼")
    game_id: str = Field(..., alias="게임ID")
    content: str = Field(..., alias="방송내용")

# 계약 상태 업데이트 스키마
class ContractStatusUpdate(BaseModel):
    status: str  # 계약 상태를 나타내는 필드
    isfree: bool
    custom_conditions: Optional[CustomConditions] = None

    class Config:
        from_attributes = True
