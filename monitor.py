import psutil
import time
import os
import stat
import win32security
import win32api
import ntsecuritycon as con
import pywintypes

def check_user_folder_rights(username, folder_path):
    try:
        # 1. Look up the User's SID
        sid, domain, sid_type = win32security.LookupAccountSid(None, username)
        
        # 2. Get the Security Descriptor of the folder
        # We need the DACL (Discretionary Access Control List)
        sd = win32security.GetFileSecurity(
            folder_path, win32security.DACL_SECURITY_INFORMATION
        )
        
        # 3. Create an impersonation token for the user
        # As Admin, we can get this without a password using a 'Linked Token' or LogonUser
        # For a simple AccessCheck, we use a restricted token
        token = win32security.LogonUser(
            username, domain, "", 
            win32security.LOGON32_LOGON_NETWORK, 
            win32security.LOGON32_PROVIDER_DEFAULT
        )

        # 4. Define the rights we want to check
        # FILE_GENERIC_READ (See), FILE_GENERIC_WRITE (Edit/Add)
        checks = {
            "Read (See)": con.FILE_GENERIC_READ,
            "Write (Edit)": con.FILE_WRITE_DATA,
            "Add Files": con.FILE_ADD_FILE
        }

        print(f"--- Rights for user '{username}' on {folder_path} ---")
        for label, mask in checks.items():
            # AccessCheck returns a tuple; the first element is a boolean (granted/denied)
            granted = win32security.AccessCheck(sd, token, mask)
            status = "YES" if granted[0] else "NO"
            print(f"{label}: {status}")

    except pywintypes.error as e:
        print(f"Error checking rights: {e.strerror}")


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
            check_user_folder_rights(sys.argv[1],p.cwd())
        except Exception:
            pass

    prev = curr
 
