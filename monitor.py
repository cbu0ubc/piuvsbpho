import psutil
import time
import os

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
            can_read = os.access(exe_path, os.R_OK)
            can_write = os.access(exe_path, os.W_OK)
            can_execute = os.access(exe_path, os.X_OK)
            print(f"  Rights - Read: {can_read}, Write: {can_write}, Execute: {can_execute}")
        except Exception:
            pass

    prev = curr
 