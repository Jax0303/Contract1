#email_utils.py
from fastapi import HTTPException, status
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

#일단 로직만 작성 , 중요한거 아님

# 발신자(자사 이메일) 설정
conf = ConnectionConfig(
    MAIL_USERNAME="company_email@example.com",  # 자사 이메일 계정, 일단은 더미 로두고 나중에 IMAP랑 SMTP 부분 해야할듯한
    MAIL_PASSWORD="company_email_password",     # 자사 이메일 비밀번호
    MAIL_FROM="company_email@example.com",      #
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

# 사용자 이메일로 초기화 링크 전송 함수
async def send_reset_email(user_email: str, token: str):
    message = MessageSchema(
        subject="Password Reset Request",
        recipients=[user_email],  # 사용자가 입력한 이메일 주소가 수신자로 설정됨
        body=f"Click the link to reset your password: http://localhost:8000/reset-password/{token}",
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)
