from pydantic import BaseModel, EmailStr, Field
from typing import List

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

# 계약 관련 스키마
class DSLContract(BaseModel):
    streamer_id: str
    game_id: str
    min_broadcast_length: int
    max_broadcast_length: int
    isfree: bool
    banned_keywords: List[str]
    no_spoilers: bool
    monetization_allowed: bool
    no_bgm_usage: bool
    no_violent_content: bool

# 방송 메타데이터 검사 관련 스키마
class BroadcastCheck(BaseModel):
    broadcast_id: str = Field(..., alias="방송ID")
    broadcast_platform: str = Field(..., alias="방송플랫폼")
    game_id: str = Field(..., alias="게임ID")
    content: str = Field(..., alias="방송내용")
