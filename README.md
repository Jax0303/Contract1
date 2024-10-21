-------------------------10/11-------------------------

코랩 

-> api요청 서버를 예시로 들어놨음 

-> 응답 성공 시 데이터를 json형식으로 파싱하여 출력 

파이참(우분투) 

-> fast api 생성 

-> cors 미들웨어 생성 

-> 구글 스프레드시트 데이터 가져옴(해결 )

-> 성공적으로 가져오면 json 형식으로 응답, 오류 발생 시 오류메시지 반환

현재 상황 :Host시트를 서버화 시켜서 작성한 데이터를 불러오는 것 까지 성공(hostAPI)까지

깃에 푸시해놧음 

목표 : Game시트도 일단 서버화를 시켜야할듯? 

의문점 : 

	1.일단 데이터를 올려놓고 수도코드의 조건으로 필요한 데이터를 끄집어내는 형식을 
 
	원하는데 이게 맞는 방식인지
 
	2. 저렇게 될려면 일단 모든 데이터(추가할 키워드 포함)를 json화 시켜야하는것 아닌가? 

---------------------10/14--------------------------

-> 시트 기반 데이터 아이디어 폐기, 사유 : 너무 귀찮음 

-> 방송 자막 분석 기능, 스포일러 및 금지 키워드 검사, 위법 내용 검사 추가

-> AI 기반 분석 추가, 방송 길이 조건 검사 추가 

미구현 기능 : 

실제 방송 메타데이터 추출

실제 방송 자막 또는 음성 데이터 분석 

AI 기반 스포일러 탐지 기능 

JWT 인증 토큰 발급 경로 

외부 API 연동

의문점 : 해당 API가 없다면 하드코딩 해야되는지, 대안은 없는지 찾아볼 것

---------------------10/15--------------------------

주요 미구현 부분
- DAO : DAO서버가 구현되어야 실질적 통신 가능 
- IPFS : 실제 IPFS 노드나 API가 구현되어야 실제 통신 로직 및 데이터 저장 가능
- 블록체인 : 블록체인 기반 수익 분배를 위한 노드 및 스마트 계약 
- 스마트 계약 : 실게 구현 및 블록체인 네트워크 연결  
- 블록체인 기반 모니터링
- 외부 API 통신은 정의만 되어있음

---------------------10/16--------------------------
- ipfs -> pds, 로직의 차이 파악 
- 일단은 변수명만 바꿔놨음 12:30
- JWT -> DID
일단은 PDS가 실제 API말고 로직API에서 구동되게 
 -> 위반 사항 및 분석 결과를 PDS에 저장되게 하고, 고유 ID값을 반환하게 했는데 이거맞음?
 -> 아니면 전자 계약서의 계약 내용을/도 저장해야 하는건지?
  
---------------------10/17--------------------------

- 방송 전에 사전에 계약 조건을 FIX하는 DSL 계약서를 
게임 ID기준으로 PDS에서 저장/불러오는게 목표  
- 사용자 인증은 JWT 사용할 것 
- 로컬 PDS는 나중에 실제 PDS 서버로 구축해야함 
        -> IsFree 조건 넣어서 구현
- OBS 에 위반 여부를 실시간으로 알려줘야 함  
- 개발 시 불러올 가이드라인에 해당하는 API는 나중에 개발(우선X) 
- 정산 분배 부분은 아직 생각 x 
- 11/30까지 백엔드,( 화면구성방식 생각해보기 ) 프론트엔드 끝나면 좋겠음. 12월 첫째주, 시연 영상, 3주차 부터 LLM 모델 개발 들어갈듯 
---------------------10/18--------------------------

사용자 정보 입력 - 검증 -해싱 구현 완료 
- 처음에 username, pw 입력 시 해당 사용자 정보가 postgredb에 저장, jwt토큰 발행
- 이 토큰을 복사해서 다음 요청 시 사용 가능 
- GET /users/me 엔드포인트로 이동하여 인증된 사용자 정보 조회 가능 
- 게임 id 기준 매핑 -> 계약서 작성시 랜덤 8자리 고유번호 발급, 이를 매핑 하여 저장 &조회
- 
  ■■■■■■■■■■■■■■■■■■■■
  남은 목표   ■■■■■■■■■■■■■■■■■■■■■■■
  
  **1.서버 확장, HTTPS 설정 -> 실서비스 환경 구축 **
  
  **2. PDS DB 백업 및 복구 구현**
  
  **3. 프론트앤드 UI 작업**
  
  ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
---------------------10/21--------------------------
외부(호스트)에서 접속 가능하게 포트포워딩 http://192.168.46.131:8000/
외부 PDS(AWS RDS)확장, FastAPI & 확장PostgreSQL 연동(커밋내용은 오타 ㅎㅎ;;)
그 외 : 어플리케이션 실행 시 자동으로 테이블 생성, 중복되지 않게 테이블명+숫자 1씩 증가 
