from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str

    class Config:
        from_attributes = True  # Pydantic V2에서 'orm_mode'는 'from_attributes'로 변경됨
