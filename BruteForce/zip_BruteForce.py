import os
import pyzipper  # zipfile 상위호환 — AES + ZipCrypto 둘 다 지원
import itertools
from multiprocessing import Manager, freeze_support
from concurrent.futures import ProcessPoolExecutor, as_completed
from colorama import init, Fore, Style

init(autoreset=True)  # colorama: print마다 색 자동 리셋

# 사전 파일 경로 (이 스크립트와 같은 폴더 기준)
BASE = os.path.dirname(os.path.abspath(__file__))
WORDLISTS = [os.path.join(BASE, name) for name in
             ("fasttrack.txt", "rockyou.txt", "wifite.txt", "crackstation.txt")]

# 브루트포스 문자셋
CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'

# 몇 번 시도마다 "다른 프로세스가 찾았나" 확인할지 (Manager 통신 비용이 있어 매번은 안 함)
CHECK_EVERY = 5000


def help_zip():
    print(f"""
{Fore.YELLOW}============ BruteForce/ZIP 사용법 ============{Fore.RESET}
  o, options   대상 zip 파일 지정
  r, run       사전공격 + 브루트포스를 여러 프로세스로 동시에 실행
  help, h      이 도움말
  exit         종료

  동작: CPU 코어를 나눠 써서 병렬로 크랙(사전 4종 + 브루트 길이 1~4 동시).
        하나가 찾으면 나머지 프로세스도 즉시 중단. 결과는 ZIP_PASSWORD.txt에 저장.
{Fore.YELLOW}==============================================={Fore.RESET}""")


def _open_zip(zip_path):
    """zip을 열고 (ZipFile, 검증용_멤버이름) 반환. 실패하면 (None, None).
    검증용 멤버는 '폴더가 아니고 크기 > 0'인 파일 (폴더/빈파일은 비번과 무관하게 열려 오탐)."""
    try:
        zf = pyzipper.AESZipFile(zip_path)  # AES·ZipCrypto 자동 처리
    except FileNotFoundError:
        return None, None
    except pyzipper.BadZipFile:
        return None, None
    files = [i for i in zf.infolist() if not i.is_dir()]
    target = next((i.filename for i in files if i.file_size > 0),
                  files[0].filename if files else None)
    if target is None:
        zf.close()
        return None, None
    return zf, target


def _try(zf, member, pwd):
    """비번 하나로 zip 안 파일 하나를 읽어본다. 맞으면 True, 틀리면 False.
    틀린 비번은 RuntimeError·BadZipFile·zlib오류 등을 던지므로 예외는 전부 실패 처리."""
    try:
        zf.read(member, pwd=pwd.encode("utf-8", errors="ignore"))
        return True
    except Exception:
        return False


# ── 워커 함수들 (별도 프로세스에서 실행됨 → 반드시 top-level이어야 pickle 됨) ──

def dict_worker(zip_path, wordlist, stop_event):
    """[워커] 사전 파일 하나를 담당해 한 줄씩 대입. 찾으면 비번 반환, 아니면 None.
    stop_event: 다른 프로세스가 먼저 찾으면 켜지는 공유 신호 → 보고 중단."""
    if not os.path.exists(wordlist):
        return None
    zf, member = _open_zip(zip_path)
    if zf is None:
        return None
    print(f"[*] 사전 시작: {os.path.basename(wordlist)}")
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i % CHECK_EVERY == 0 and stop_event.is_set():
                    return None
                pwd = line.strip()
                if pwd and _try(zf, member, pwd):
                    stop_event.set()  # 나머지 프로세스도 멈추게 신호
                    return pwd
    finally:
        zf.close()
    return None


def brute_worker(zip_path, start_len, end_len, stop_event):
    """[워커] start_len~end_len 길이 범위의 모든 조합을 대입. 찾으면 비번 반환, 아니면 None."""
    zf, member = _open_zip(zip_path)
    if zf is None:
        return None
    print(f"[*] 브루트 시작: 길이 {start_len}~{end_len - 1}")
    try:
        count = 0
        for length in range(start_len, end_len):
            for combo in itertools.product(CHARS, repeat=length):
                count += 1
                if count % CHECK_EVERY == 0 and stop_event.is_set():
                    return None
                pwd = "".join(combo)
                if _try(zf, member, pwd):
                    stop_event.set()
                    return pwd
    finally:
        zf.close()
    return None


def crack(zip_path):
    """사전 4종 + 브루트 3구간을 여러 프로세스로 동시에 돌린다.
    하나가 찾으면 stop_event로 전체 중단."""
    # 대상 zip이 열리는지 먼저 확인 (없는 파일/깨진 zip이면 프로세스 띄우기 전에 걸러냄)
    zf, member = _open_zip(zip_path)
    if zf is None:
        print(f"[!] zip을 열 수 없음(파일 없음/깨짐): {zip_path}")
        return
    zf.close()

    found_pw = None
    with Manager() as manager:
        stop_event = manager.Event()  # 프로세스 간 공유되는 '찾음' 신호
        # max_workers 기본값 = os.cpu_count() (코어 수만큼 병렬)
        with ProcessPoolExecutor() as executor:
            futures = []
            # 사전공격 4개
            for wl in WORDLISTS:
                futures.append(executor.submit(dict_worker, zip_path, wl, stop_event))
            # 브루트포스: 길이 1~2 / 3 / 4 를 각각 다른 프로세스에 (길수록 무거워 분리)
            for (s, e) in ((1, 3), (3, 4), (4, 5)):
                futures.append(executor.submit(brute_worker, zip_path, s, e, stop_event))

            for fut in as_completed(futures):
                try:
                    result = fut.result()
                    if result is not None and found_pw is None:
                        found_pw = result
                except Exception as ex:
                    print("[워커 예외]", type(ex).__name__, ex)

    if found_pw is not None:
        print(f"[+] 찾았다! 비밀번호: {Fore.GREEN}{found_pw}{Style.RESET_ALL}")
        with open("ZIP_PASSWORD.txt", "a", encoding="utf-8") as fp:
            fp.write(f"{zip_path} : {found_pw}\n")
    else:
        print("[!] 비밀번호를 찾지 못함 (사전 + 길이4 브루트 소진)")


def start_attack():
    """모듈 메인 루프. options로 zip 지정, run으로 크랙."""
    zip_path = None
    while True:
        cmd = input(f"{Fore.BLUE}0x08{Fore.RESET}"
                    f"(/{Fore.YELLOW}BruteForce{Fore.RESET}/{Fore.YELLOW}ZIP{Fore.RESET})>>").split()
        if not cmd:
            continue
        if cmd[0] == "exit":
            print("종료...")
            return
        elif cmd[0] in ("help", "h"):
            help_zip()
        elif cmd[0] in ("o", "options"):
            name = input(f"{Fore.RED}ZIP File Name{Fore.RESET}:")
            # 입력값 그대로 / 현재폴더 / 이 스크립트 폴더 순으로 찾는다
            candidates = [name, os.path.join(os.getcwd(), name), os.path.join(BASE, name)]
            zip_path = next((p for p in candidates if os.path.isfile(p)), None)
            if zip_path is None:
                print(f"[!] 파일 없음: {name}")
            else:
                print(f"{Fore.GREEN}OK{Fore.RESET}!! → {zip_path}")
        elif cmd[0] in ("r", "run"):
            if zip_path is None:
                print("[!] 먼저 o(options)로 zip 파일을 지정하세요.")
                continue
            print("Attacking...")
            crack(zip_path)


if __name__ == "__main__":
    freeze_support()  # Windows에서 multiprocessing 쓸 때 필수 (없으면 프로세스 무한 생성)
    start_attack()
