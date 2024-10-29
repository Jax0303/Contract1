from sqlalchemy.orm import Session
from models import User, Contract, Guideline
from schemas import UserCreate
from fastapi import HTTPException, status

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def create_user(db: Session, user: UserCreate):
    from auth import get_password_hash  # get_password_hash 임포트, 함수 내부로 이동
    # 중복 사용자 확인
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists. Please choose a different username."
        )
    #비밀번호 해싱
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password, email=user.email)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def create_guideline(db: Session, content: str):
    guideline = Guideline(content=content)
    db.add(guideline)
    db.commit()
    db.refresh(guideline)
    return guideline

def get_guidelines(db: Session):
    return db.query(Guideline).all()


def save_contract(contract, db: Session):
    db.add(contract)
    db.commit()
    db.refresh(contract)
    return contract

def get_contract_by_pds_id(pds_id: str, db: Session):
    return db.query(Contract).filter(Contract.pds_id == pds_id).first()

def check_contract(broadcast, db: Session):
    contract = get_contract_by_pds_id(broadcast.game_id, db)
    if contract and contract.isfree:
        # 방송 조건 및 위반 검사를 위한 로직 구현
        return {"message": "Contract is valid"}
    return {"message": "Contract violated"}

def get_users(db: Session):
    return db.query(User).all()#모든 사용자 조회

