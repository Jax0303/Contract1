import requests

# API 엔드포인트 URL
url = "http://127.0.0.1:8000/check_broadcast"

# 요청에 포함할 데이터 (계약서 조건과 방송 ID 및 플랫폼)
data = {
    "방송ID": "abc123",
    "방송플랫폼": "YouTube"
}

# POST 요청 보내기
response = requests.post(url, json=data)

# 응답 결과 출력
if response.status_code == 200:
    print("API 요청 성공:", response.json())
else:
    print(f"API 요청 실패, 상태 코드: {response.status_code}")
