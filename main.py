#main.py
from fastapi import FastAPI, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from auth import authenticate_user, create_access_token, create_reset_token
from crud import (
    create_user, get_users, save_contract, check_contract,
    create_customcondition, get_customcondition, get_contract_by_game_id, update_contract_status
)
from email_utils import send_reset_email
from database import get_db
from schemas import UserCreate, UserResponse, DSLContract, ResetPasswordRequest, BroadcastCheck, ContractStatusUpdate
from log_utils import log_error

app = FastAPI()

# OAuth2 설정
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/users/", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    return create_user(db, user)

@app.get("/users/", response_model=list[UserResponse])
def read_users(db: Session = Depends(get_db)):
    return get_users(db)

@app.post("/login")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, int(form_data.username), form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="ID 또는 비밀번호를 확인하세요")

    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_reset_token(data={"sub": user.username})
    response.set_cookie("access_token", access_token, httponly=True)
    response.set_cookie("refresh_token", refresh_token, httponly=True)
    return {"message": "Login successful"}

@app.post("/request-password-reset")
async def request_password_reset(email: str):
    token = create_reset_token(email)
    await send_reset_email(email, token)
    return {"message": "Password reset email sent"}

@app.post("/reset-password")
async def reset_password(request: ResetPasswordRequest):
    email = verify_reset_token(request.token)
    if email is None:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    update_password(email, request.new_password)
    return {"message": "Password reset successfully"}

@app.post("/contract/save")
def save_contract_api(contract: DSLContract, db: Session = Depends(get_db)):
    # Streamer와 Developer 서명 상태에 따라 계약 상태 결정
    if contract.streamer_signed and contract.developer_signed:
        contract.status = "completed"  # 양측 모두 서명 시 '계약 완료'
    else:
        contract.status = "in_progress"  # 한쪽만 서명 시 '계약 진행 중'

    return save_contract(contract, db)

@app.get("/contract/{game_id}")
def get_contract_api(game_id: str, db: Session = Depends(get_db)):
    return get_contract_by_game_id(game_id, db)

@app.post("/check_contract")
def check_contract_api(broadcast: BroadcastCheck, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    return check_contract(broadcast, db)

@app.post("/upload-customcondition")
def upload_customcondition(content: str, db: Session = Depends(get_db)):
    return create_customcondition(db, content)

@app.get("/customcondition")
def get_customcondition_api(db: Session = Depends(get_db)):
    return get_customcondition(db)

@app.patch("/contract/{contract_id}/status")
def update_contract_status_api(contract_id: str, status: ContractStatusUpdate, db: Session = Depends(get_db)):
    return update_contract_status(db, contract_id, status)

@app.get("/contracts/")
def get_contracts_by_status(status: str = None, db: Session = Depends(get_db)):
    return get_contracts_by_filter(db, status=status)
