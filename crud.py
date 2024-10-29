from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound
from models import User, Contract, Guideline
from schemas import UserCreate, ContractStatusUpdate
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
            detail="중복된 사용자명입니다."
        )
    # 비밀번호 해싱
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
    db_contract = Contract(
        title=contract.title,
        streamer_id=contract.streamer_id,
        game_id=contract.game_id,
        min_broadcast_length=contract.min_broadcast_length,
        max_broadcast_length=contract.max_broadcast_length,
        isfree=contract.isfree,
        custom_conditions=contract.custom_conditions.dict() if contract.custom_conditions else None,
        streamer_signed=contract.streamer_signed,
        developer_signed=contract.developer_signed,
        status=contract.status,
    )
    db.add(db_contract)
    db.commit()
    db.refresh(db_contract)
    return db_contract

def get_contract_by_game_id(game_id: str, db: Session):
    return db.query(Contract).filter(Contract.game_id == game_id).first()

def check_contract(broadcast, db: Session):
    contract = get_contract_by_game_id(broadcast.game_id, db)
    if contract:
        if contract.isfree:
            # 맞춤형 조건에 따라 방송 조건 검사 로직 구현 (예: banned_keywords 등)
            violations = []
            if contract.custom_conditions:
                if contract.custom_conditions['no_spoilers'] and "spoiler" in broadcast.content:
                    violations.append("스포일러 포함")
                if any(keyword in broadcast.content for keyword in contract.custom_conditions['banned_keywords']):
                    violations.append("금지된 키워드 포함")
            return {"message": "Contract is valid"} if not violations else {"message": "Contract violated", "violations": violations}
    return {"message": "No contract found"}

def update_contract_status(db: Session, contract_id: int, status_update: ContractStatusUpdate):
    try:
        contract = db.query(Contract).filter(Contract.id == contract_id).one()
        contract.status = status_update.status
        if contract.isfree:
            # 맞춤형 조건을 적용할 수 있도록 custom_conditions 업데이트
            contract.custom_conditions = status_update.custom_conditions.dict() if status_update.custom_conditions else None
        db.commit()
        db.refresh(contract)
        return contract
    except NoResultFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contract not found")


def get_users(db: Session):
    return db.query(User).all()  # 모든 사용자 조회
