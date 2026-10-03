0xCC

보안 학습·방어 검증용 공격 시뮬레이션 프레임워크 (Python, Windows)

하나의 콘솔(0x08>>)에서 사전·무차별 대입, DoS, ARP/DNS 스푸핑, 피싱 페이지, 프록시 로테이션 등 공격 기법을 모듈 형태로 실행하며 각 기법의 동작 원리와 방어 포인트를 학습하기 위한 도구다. 제작자 alias: EDA

⚠️ 법적 고지 / 사용 범위

본인 소유이거나 명시적으로 서면 허가받은 '격리된 랩 네트워크'에서만 사용해야 합니다.

이 프레임워크의 모든 모듈(무차별 대입, DoS, ARP/DNS 스푸핑, 피싱 페이지 등)은 타인의 시스템·계정·네트워크를 대상으로 사용할 경우 정보통신망법, 통신비밀보호법, 개인정보보호법 등 관련 법률 위반이며, 그로 인한 모든 책임은 사용자 본인에게 있습니다.

본 프로젝트는 보안 교육 및 방어 기법 검증을 목적으로만 제공되며, 실제 서비스·타인 자산을 대상으로 한 사용은 어떤 경우에도 허용되지 않습니다.

테스트는 VMware 등으로 구성한 host-only / internal 네트워크의 자체 실습용 서버에서만 수행하십시오.

요구 사항
Python 3.x (Windows)
패키지: scapy, requests, colorama, art, tabulate, python-dotenv, pymysql, wcwidth
bash
  pip install scapy requests colorama art tabulate python-dotenv pymysql wcwidth
DNS 스푸핑 모듈: 관리자 권한 + Npcap 설치 (설치 시 WinPcap API-compatible Mode 체크)
피싱/DB 모듈: MySQL 서버 + .env에 접속 정보 (단, Website/ 코드는 이 리포에 미포함 — 아래 참고)
.env 예시 (리포에는 포함하지 않음)
DB_HOST=127.0.0.1
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=0xcc
실행
bash
python 0xCC.py

또는 Windows 실행파일(PyInstaller)로 빌드해 사용. 빌드한 exe는 서브모듈(.py)·.venv·url/·data/ 폴더와 같은 위치에 있어야 각 모듈이 정상 실행된다.

실행하면 0x08>> 프롬프트가 뜬다. help로 전체 명령을 볼 수 있다.

명령어
📦 생성
명령	설명
create backdoor/x64/windows/tcp	리버스 셸(백도어) exe 생성 — 현재 비활성화됨 (아래 참고)
🧩 모듈 실행 (use)
명령	설명
use bruteforce/web	웹 로그인 폼 사전공격 + 무차별 대입
use bruteforce/zip	암호 걸린 zip 파일 비밀번호 크랙
use website/naver	네이버 스타일 피싱 페이지 (자격증명 수집 실습) — 코드 미포함, 아래 참고
use website/google	구글 스타일 피싱 페이지 (자격증명 수집 실습) — 코드 미포함, 아래 참고
use backdoor/x64/windows/tcp	백도어 리스너(셸) — 현재 비활성화됨
🌐 네트워크
명령	설명
dnsspoof	ARP 스푸핑으로 MITM 후 DNS 질의를 위조 응답으로 유도
🔀 프록시
명령	설명
proxy sys <proxy>	프록시 등록 (예: socks5h://1.2.3.4:1080)
proxy list	등록된 프록시 목록
proxy del <번호>	번호로 프록시 삭제 (proxy list의 번호)
proxy clear	등록된 프록시 전부 삭제
proxy mode on / off	프록시 모드 켜기 / 끄기
proxy status	현재 프록시 모드 상태
💥 DoS
명령	설명
dos --http <url>	HTTP GET 플러딩
dos --http p=<n> a=<n> <url>	프로세스 수(p) / 비동기 워커 수(a) 지정
dos -s <url/ip> [port=N] [p=N]	Slowloris (연결을 오래 점유해 소켓 고갈 유도)
🗄️ DB 조회 (수집 데이터)
명령	설명
db <naver|google>	수집 테이블 전체 조회
db <naver|google> search <아이디>	특정 아이디 검색
db <naver|google> delete <아이디>	특정 아이디 삭제
기타
명령	설명
help, h	도움말
exit	종료
모듈별 상세
bruteforce/web — 웹 로그인 브루트포스
options로 타겟 설정 → run으로 공격 시작
먼저 랜덤(틀린) 비번 10개를 보내 "실패했을 때의 응답"을 기준값으로 수집
이후 시도가 로그인 성공의 적극적 증거(실패 땐 없던 세션 쿠키 생성 / 성공 리다이렉트 / 상태코드 변화)를 보일 때만 성공으로 판정 — 단순히 "실패 응답과 다름"은 성공으로 치지 않아 오탐(빈 비번·캡차·레이트리밋 등)을 거른다
성공 시 S_ID_PASSWORD.txt에 저장

타겟 설정 파일 (리포에는 미포함):

url/<이름>.json → {"url": "공격할 로그인 POST 주소"}
data/<이름>.json → 로그인 폼 데이터. 아이디·비번 자리는 null 예: {"siteId":"13", "mid":null, "pwd":null} (null 자리 2개를 id/pw로 자동 감지)
dnsspoof — ARP + DNS 스푸핑 (MITM)

ARP 스푸핑으로 피해자↔게이트웨이 사이에 끼어든 뒤, DNS 질의(UDP 53)를 가로채 진짜 응답보다 먼저 위조 응답을 보내 원하는 IP로 유도한다. IP 포워딩 자동 토글, 종료 시 ARP 캐시 자동 복구.

같은 L2 세그먼트에서만 동작하며, 피해자가 DoH/DoT를 쓰면 평문 DNS 위조가 통하지 않음 (요즘 브라우저 기본값). HTTPS + HSTS 사이트도 DNS를 바꿔도 차단됨 → 그 자체가 방어 포인트.
proxy — 프록시 로테이션

등록한 프록시를 요청마다 로테이션하고, 연속 실패 시 일정 시간 격리(quarantine)한다. proxy mode on으로 켜면 지원 모듈이 프록시를 경유하고, 전부 죽으면 공격을 중단한다. 설정은 config 파일에 영속 저장된다.

website/naver · website/google — 피싱 페이지 (⚠️ 코드 미포함)

자격증명 입력 흐름을 재현한 실습용 로그인 페이지. 입력값은 DB에 저장되며 db 명령으로 조회한다. (피싱 인지·방어 교육용.)

이 공개 리포에는 Website/ 디렉터리(피싱 페이지·DB 코드)를 의도적으로 포함하지 않았습니다. 실제로 자격증명을 수집·저장하는 코드라 오·남용을 막기 위해 공개하지 않습니다. 따라서 use website/*, db 명령과, 0xCC.py의 from Website import db 의존 부분은 이 리포만으로는 동작하지 않습니다 (코드 열람·학습용 공개). 같은 이유로 backdoor/, scan/ 디렉터리도 비공개입니다.

⛔ 현재 비활성화: 백도어(리버스 셸) 생성

create backdoor/x64/windows/tcp 및 use backdoor/... (리스너)는 현재 정상 동작하지 않으며 생성할 수 없습니다. 추후 수정 예정이며, 그때까지 해당 기능은 사용 불가 상태입니다.

방어 관점 (같이 보면 좋음)

각 공격이 현실에서 왜 점점 안 통하는지가 곧 방어 포인트다.

브루트포스 → 레이트리밋, 계정 잠금, CAPTCHA, MFA, 비정상 로그인 탐지
DNS 스푸핑 → DNSSEC, DoH/DoT, 정적 ARP / DAI·DHCP 스누핑, HTTPS+HSTS
DoS → 레이트리밋, 리버스 프록시/CDN, SYN 쿠키, 연결 타임아웃·동시연결 제한
피싱 → URL·인증서 확인, MFA, 비밀번호 관리자(도메인 불일치 시 자동입력 안 됨)
라이선스

MIT License — 단, 상단 법적 고지의 사용 범위를 반드시 준수할 것.
