import psutil
import time
import os
import sys
import stat
import win32security
import ntsecuritycon as con


import win32security
import ntsecuritycon as con

def check_user_access_manual(username, path):
    try:
        # 1. Get the SID for the user
        target_sid, domain, sid_type = win32security.LookupAccountName(None, username)
        
        # 2. Get the Security Descriptor and the DACL
        sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        
        if dacl is None:
            print("No DACL found (Inherited/System protected).")
            return

        
        has_write = False
        
        # 3. Loop through every Access Control Entry (ACE)
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            # ace[0] = Header (Type), ace[1] = Mask (Rights), ace[2] = SID
            ace_type = ace[0][0]
            ace_mask = ace[1]
            ace_sid = ace[2]

            # Check if this rule applies to our user
            if ace_sid == target_sid:
                # Check for Write Data or Generic Write
                write_bits = con.FILE_WRITE_DATA | con.FILE_GENERIC_WRITE
                
                if ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:
                    if ace_mask & write_bits:
                        has_write = True
                elif ace_type == win32security.ACCESS_DENIED_ACE_TYPE:
                    if ace_mask & write_bits:
                        print("Found an explicit DENY for write.")
                        has_write = False
                        break # Deny always overrides Allow

        return has_write

    except Exception as e:
        print(f"Error: {e}")
        return False

prev = set(psutil.pids())

print(f"[*] psutil process monitor started for user {sys.argv[1]}")

while True:
    time.sleep(0.1)
    curr = set(psutil.pids())

    for pid in curr - prev:
        try:
            p = psutil.Process(pid)
            if(check_user_access_manual(sys.argv[1],p.cwd())):
                print("\n[+] PROCESS STARTED")
                print(f"  PID : {pid}")
                print(f"  USER: {p.username()}")
                print(f"  NAME: {p.name()}")
                print(f"  CMD : {' '.join(p.cmdline())}")
                exe_path=p.exe()
                print(f"  PATH: {exe_path}")
        except Exception:
            pass

    prev = curr
 
