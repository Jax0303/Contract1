from fastapi import FastAPI, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from auth import authenticate_user, create_access_token, create_reset_token
from crud import create_user, get_users, save_contract, get_contract_by_pds_id, check_contract, create_guideline, get_guidelines
from email_utils import send_reset_email
from database import get_db
from schemas import UserCreate, UserResponse, DSLContract, ResetPasswordRequest, BroadcastCheck
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


@app.post("/token")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})
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
    return save_contract(contract, db)


@app.get("/contract/{pds_id}")
def get_contract_api(pds_id: str, db: Session = Depends(get_db)):
    return get_contract_by_pds_id(pds_id, db)


@app.post("/check_contract")
def check_contract_api(broadcast: BroadcastCheck, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    return check_contract(broadcast, db)


@app.post("/upload-guideline")
def upload_guideline(content: str, db: Session = Depends(get_db)):
    return create_guideline(db, content)


@app.get("/guidelines")
def get_guidelines_api(db: Session = Depends(get_db)):
    return get_guidelines(db)
