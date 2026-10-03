# proxy.py — 0xCC proxy layer
# 브루트포스 등 네트워크 요청을 프록시(단일/로테이션)로 라우팅.
# requests(HTTP) / socket(TCP) 둘 다 지원. 인가받은 테스트에만 사용할 것.
#
# deps: pip install "requests[socks]" PySocks

import json
import os
import random
import socket
import threading
import time
from contextlib import contextmanager
from urllib.parse import quote, urlparse

try:
    import requests
except ImportError:
    requests = None


class ProxyExhausted(RuntimeError):
    """strict 모드에서 살아있는 프록시가 없을 때."""


class Proxy:
    """파싱된 단일 프록시. scheme://[user:pass@]host:port"""
    __slots__ = ("scheme", "host", "port", "user", "password", "fails", "last_fail")

    def __init__(self, raw):
        raw = raw.strip()
        parsed = urlparse(raw if "://" in raw else "http://" + raw)
        self.scheme = (parsed.scheme or "http").lower()
        self.host = parsed.hostname
        self.port = parsed.port
        self.user = parsed.username
        self.password = parsed.password
        self.fails = 0          # 연속 실패 횟수
        self.last_fail = 0.0
        if not self.host or not self.port:
            raise ValueError(f"잘못된 프록시 형식: {raw}")

    @property
    def url(self):
        # user/pass에 @ : / 등 특수문자가 있어도 깨지지 않게 percent-encode.
        auth = ""
        if self.user:
            auth = quote(self.user, safe="")
            if self.password:
                auth += ":" + quote(self.password, safe="")
            auth += "@"
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    def requests_dict(self):
        # http/https 둘 다 같은 프록시로. socks5h:// 로 주면 DNS도 프록시에서 해결.
        return {"http": self.url, "https": self.url}

    def __repr__(self):
        return f"<Proxy {self.scheme}://{self.host}:{self.port}>"


class ProxyManager:
    def __init__(self, proxies=None, file=None, strategy="round_robin",
                 max_fails=3, cooldown=60, strict=False):
        """
        proxies : 단일 문자열 또는 리스트
        file    : 한 줄에 하나씩 적힌 프록시 목록 파일 (# 주석 허용)
        strategy: 'round_robin' | 'random'
        max_fails: 이 횟수 연속 실패 시 프록시 격리
        cooldown : 격리 후 재투입까지 대기(초)
        strict  : True면 살아있는 프록시가 없을 때 직접 연결로 새지 않고
                  ProxyExhausted 예외를 던짐 (익명성 목적일 때 실제 IP 노출 방지).
                  이 경우 풀이 전부 죽으면 요청이 '중단'됨 — 누수보다 중단이 낫다.
        """
        self.lock = threading.Lock()
        self.strategy = strategy
        self.max_fails = max_fails
        self.cooldown = cooldown
        self.strict = strict
        self._idx = 0
        self._warned_empty = False
        self.proxies = []

        items = []
        if proxies:
            items += proxies if isinstance(proxies, (list, tuple)) else [proxies]
        if file:
            with open(file, encoding="utf-8") as f:
                items += [ln for ln in (l.strip() for l in f)
                          if ln and not ln.startswith("#")]
        for it in items:
            try:
                self.proxies.append(Proxy(it))
            except ValueError as e:
                print(f"[proxy] skip: {e}")

    def __bool__(self):
        return bool(self.proxies)

    def _quarantined(self, p, now):
        return p.fails >= self.max_fails and now - p.last_fail < self.cooldown

    def _exhausted(self):
        # lock 안에서 호출됨.
        if not self.proxies:
            return None                       # 애초에 프록시 미설정 → 직접 연결(의도된 동작)
        if self.strict:
            raise ProxyExhausted("살아있는 프록시 없음 (strict) — 요청 중단")
        if not self._warned_empty:
            print("[proxy] 경고: 살아있는 프록시 없음 → 직접 연결(실제 IP)로 나감")
            self._warned_empty = True
        return None

    def get(self):
        """다음 사용할 프록시 1개.
        쓸 게 없으면 strict=False면 None(직접 연결), strict=True면 ProxyExhausted."""
        with self.lock:
            n = len(self.proxies)
            if n == 0:
                return self._exhausted()
            now = time.time()
            if self.strategy == "random":
                alive = [p for p in self.proxies if not self._quarantined(p, now)]
                if not alive:
                    return self._exhausted()
                self._warned_empty = False
                return random.choice(alive)
            # round_robin: 고정 순서(self.proxies)로 커서 전진 + 죽은 건 skip.
            # alive만 모아 modulo 하면 크기가 변할 때 순환이 밀리므로 이렇게 함.
            for _ in range(n):
                p = self.proxies[self._idx % n]
                self._idx = (self._idx + 1) % n
                if not self._quarantined(p, now):
                    self._warned_empty = False
                    return p
            return self._exhausted()

    def requests_proxies(self):
        """requests의 proxies= 에 바로 넣을 dict와 사용한 Proxy를 반환.
        로테이션은 이 호출마다 1칸 전진하므로 '요청마다' 새로 부를 것.
        (받은 dict를 재사용하면 계속 같은 프록시만 쓴다.)"""
        p = self.get()
        return (p.requests_dict() if p else None), p

    def report(self, proxy, ok):
        """요청 결과 피드백. 실패 누적 시 해당 프록시 자동 격리.
        이걸 호출하지 않으면 죽은 프록시가 영원히 안 걸러진다 — lease() 참고."""
        if proxy is None:
            return
        with self.lock:
            if ok:
                proxy.fails = 0
            else:
                proxy.fails += 1
                proxy.last_fail = time.time()

    @contextmanager
    def lease(self):
        """per-request용 컨텍스트 매니저 — 빠져나올 때 성공/실패 자동 report.
            with mgr.lease() as (proxies, p):
                r = requests.get(url, proxies=proxies, timeout=5)
        예외가 나면 실패로 기록(=전송 단계 실패). 주의: 프록시가 407/502 같은
        '상태코드'로 죽으면 예외가 안 나므로 자동 격리가 안 된다 — 그런 경우엔
        블록 안에서 상태 보고 mgr.report(p, False) 하거나 raise 할 것.
        세션에 프록시를 박아 재사용하는 패턴(브루트포스 스레드별 세션)에는
        맞지 않음 — 거긴 수동 report가 맞다."""
        p = self.get()
        proxies = p.requests_dict() if p else None
        ok = True
        try:
            yield proxies, p
        except Exception:
            ok = False
            raise
        finally:
            self.report(p, ok)

    def validate(self, test_url="http://httpbin.org/ip", timeout=8):
        """죽은 프록시 제거. 살아있는 개수 반환.
        네트워크 I/O 동안 lock을 쥐지 않으므로 '셋업 때 단독으로'만 호출할 것
        (동시에 get()이 돌면 레이스)."""
        if requests is None:
            raise RuntimeError('requests 필요: pip install "requests[socks]"')
        good = []
        for p in self.proxies:
            try:
                r = requests.get(test_url, proxies=p.requests_dict(), timeout=timeout)
                if r.ok:
                    good.append(p)
                    print(f"[proxy] OK   {p}")
                else:
                    print(f"[proxy] dead {p} ({r.status_code})")
            except Exception as e:
                print(f"[proxy] dead {p} ({type(e).__name__})")
        with self.lock:
            self.proxies = good
            self._idx = 0
            self._warned_empty = False
        return len(good)

    def open_socket(self, dst_host, dst_port, timeout=10):
        """프록시를 거친 '연결된 소켓'과 사용한 Proxy를 반환.
        strict=False면 프록시 없을 때 직접 연결, strict=True면 ProxyExhausted.
        (메서드명이 socket 모듈과 겹치지 않게 open_socket으로.) PySocks 필요."""
        p = self.get()
        if p is None:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((dst_host, dst_port))
            return s, None

        import socks
        kind = {"socks5": socks.SOCKS5, "socks5h": socks.SOCKS5,
                "socks4": socks.SOCKS4, "http": socks.HTTP}.get(p.scheme)
        if kind is None:
            raise ValueError(f"소켓 프록시 미지원 scheme: {p.scheme}")
        s = socks.socksocket()
        s.settimeout(timeout)
        # requests 경로와 DNS 동작을 일치시킴: socks5h만 원격 DNS, socks5는 로컬.
        s.set_proxy(kind, p.host, p.port,
                    username=p.user, password=p.password,
                    rdns=(p.scheme == "socks5h"))
        s.connect((dst_host, dst_port))
        return s, p


# ─────────────────────────────────────────────────────────────
# 전역 proxy mode — main에서 토글, 요청형 모듈들이 공유
# ─────────────────────────────────────────────────────────────

_active: "ProxyManager | None" = None


def enable(proxies=None, file=None, **kwargs):
    """proxy mode ON. ProxyManager 생성해 전역 등록 후 반환.
    누수 방지가 필요하면 enable(file=..., strict=True)."""
    global _active
    _active = ProxyManager(proxies=proxies, file=file, **kwargs)
    return _active


def disable():
    """proxy mode OFF."""
    global _active
    _active = None


def active():
    """켜져 있으면 ProxyManager, 꺼져 있으면 None."""
    return _active


def is_on():
    return _active is not None


# ─────────────────────────────────────────────────────────────
# 영구 저장 설정 — 'proxy sys'로 등록한 프록시 서버 보관
# ─────────────────────────────────────────────────────────────

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "proxy_config.json")

_DEFAULTS = {
    "proxies": [],            # "scheme://[user:pass@]host:port" 문자열 목록
    "strategy": "round_robin",
    "strict": True,           # 저장 설정 기본은 누수 방지(True)
    "max_fails": 3,
    "cooldown": 60,
}


def load_config(path=CONFIG_PATH):
    """저장된 설정 로드. 파일이 없거나 깨졌으면 기본값."""
    cfg = dict(_DEFAULTS)
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            cfg.update({k: v for k, v in data.items() if k in _DEFAULTS})
        except (json.JSONDecodeError, OSError) as e:
            print(f"[proxy] config 로드 실패({type(e).__name__}) — 기본값 사용")
    return cfg


def save_config(cfg, path=CONFIG_PATH):
    """설정 저장."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def enable_from_config(path=CONFIG_PATH):
    """저장된 설정으로 proxy mode ON.
    저장된 프록시가 하나도 없으면 켜지 않고 None 반환('서버 없음' 판정용)."""
    cfg = load_config(path)
    if not cfg["proxies"]:
        return None
    global _active
    _active = ProxyManager(
        proxies=cfg["proxies"],
        strategy=cfg["strategy"],
        strict=cfg["strict"],
        max_fails=cfg["max_fails"],
        cooldown=cfg["cooldown"],
    )
    return _active


def add_proxy(raw):
    """저장 목록에 추가. 반환 ('added', 총개수) / ('dup', raw) / ('invalid', 메시지)"""
    try:
        Proxy(raw)                       # 형식 검증
    except ValueError as e:
        return ("invalid", str(e))
    cfg = load_config()
    if raw in cfg["proxies"]:
        return ("dup", raw)
    cfg["proxies"].append(raw)
    save_config(cfg)
    return ("added", len(cfg["proxies"]))


def remove_proxy(index):
    """번호로 삭제. 반환: 삭제된 문자열 또는 None(범위 밖)."""
    cfg = load_config()
    if not (0 <= index < len(cfg["proxies"])):
        return None
    removed = cfg["proxies"].pop(index)
    save_config(cfg)
    return removed


def clear_proxies():
    """전부 삭제. 반환: 지운 개수."""
    cfg = load_config()
    n = len(cfg["proxies"])
    if n:
        cfg["proxies"].clear()
        save_config(cfg)
    return n


def list_proxies():
    """저장 설정 반환."""
    return load_config()
