import re
from pydantic import BaseModel, validator, ValidationError, field_validator
from passlib.context import CryptContext

# bcrypt 비밀번호 해싱 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCreate(BaseModel):
    username: str
    password: str

    # ID 조건 유효성 검사
    @field_validator("username")
    def validate_username(cls, value):
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]{4,14}$", value):
            raise ValueError("ID는 5~15자 사이의 영문 대소문자, 숫자, 언더스코어만 허용하며 첫 글자는 문자로 시작해야 합니다.")
        return value

    # PW 조건 유효성 검사
    @field_validator("password")
    def validate_password(cls, value):
        # 길이 검사
        if not (8 <= len(value) <= 20):
            raise ValueError("비밀번호는 최소 8자 이상, 최대 20자 이하여야 합니다.")
        # 대문자, 소문자, 숫자, 특수 문자 포함 여부 검사
        if not re.search(r"[A-Z]", value):
            raise ValueError("비밀번호에는 적어도 하나의 대문자가 포함되어야 합니다.")
        if not re.search(r"[a-z]", value):
            raise ValueError("비밀번호에는 적어도 하나의 소문자가 포함되어야 합니다.")
        if not re.search(r"[0-9]", value):
            raise ValueError("비밀번호에는 적어도 하나의 숫자가 포함되어야 합니다.")
        if not re.search(r"[!@#$%^&*]", value):
            raise ValueError("비밀번호에는 적어도 하나의 특수 문자(!@#$%^&*)가 포함되어야 합니다.")
        # 공백 포함 금지
        if re.search(r"\s", value):
            raise ValueError("비밀번호에는 공백이 포함될 수 없습니다.")
        # 연속 문자 검사
        if re.search(r"(.)\1{2,}", value):
            raise ValueError("비밀번호에 연속된 문자가 포함될 수 없습니다.")
        return value

        # 비밀번호 해싱 함수
    def get_hashed_password(self):
        return pwd_context.hash(self.password)

class UserResponse(BaseModel):
    username: str

    class Config:
        from_attributes = True
