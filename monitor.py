import psutil
import time
import os
import stat

prev = set(psutil.pids())

print("[*] psutil process monitor started")

while True:
    time.sleep(0.1)
    curr = set(psutil.pids())

    for pid in curr - prev:
        try:
            p = psutil.Process(pid)
            print("\n[+] PROCESS STARTED")
            print(f"  PID : {pid}")
            print(f"  USER: {p.username()}")
            print(f"  NAME: {p.name()}")
            print(f"  CMD : {' '.join(p.cmdline())}")
            exe_path=p.exe()
            print(f"  PATH: {exe_path}")
            file_stat = os.stat(exe_path)
            mode = file_stat.st_mode
            print(f"  Octal permissions: {oct(stat.S_IMODE(mode))}")
            is_world_writable = bool(mode & stat.S_IWOTH)
            print(f"  Is world writable: {is_world_writable}")
        except Exception:
            pass

    prev = curr
 
