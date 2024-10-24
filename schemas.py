from pydantic import BaseModel,EmailStr,field_validator
from typing import List

# 사용자 관련 스키마 정의
from pydantic import EmailStr

# 사용자 관련 스키마 정의
class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr  # 이메일 필드 추가

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr  # 이메일 검증

    class Config:
        from_attributes = True

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

    # Pydantic V2 스타일의 유효성 검증
    @field_validator('min_broadcast_length')
    def check_min_length(cls, value):
        if value < 0:
            raise ValueError('Minimum broadcast length cannot be negative')
        return value
