import json

# Threat Hunting Script: LOLBins Detection
# Focus: T1105 (Ingress Tool Transfer), T1059.001 (PowerShell)

# Dictionary of targeted LOLBins and their suspicious arguments
LOLBINS_SIGNATURES = {
    "certutil.exe": ["-urlcache", "-split", "-f"],
    "powershell.exe": ["-enc", "-encodedcommand", "hidden"],
    "bitsadmin.exe": ["/transfer", "/download"],
    "mshta.exe": ["http", "https"]
}

def hunt_lolbins(log_file):
    print(f"[*] Initiating Threat Hunt on {log_file}...\n")
    alerts_triggered = 0

    try:
        with open(log_file, 'r') as file:
            logs = json.load(file)
            
            for event in logs:
                cmd_line = event.get("CommandLine", "").lower()
                process = event.get("ProcessName", "").lower()
                
                # Check if the process is a known LOLBin
                if process in LOLBINS_SIGNATURES:
                    # Check if suspicious arguments are used
                    for arg in LOLBINS_SIGNATURES[process]:
                        if arg in cmd_line:
                            print(f"[!] THREAT DETECTED: Suspicious {process} execution")
                            print(f"    Timestamp:   {event.get('Timestamp')}")
                            print(f"    Host:        {event.get('HostName')}")
                            print(f"    CommandLine: {event.get('CommandLine')}\n")
                            alerts_triggered += 1
                            break # Move to next event after flagging

        print(f"[*] Hunt Complete. Total suspicious events found: {alerts_triggered}")
        
    except FileNotFoundError:
        print("[!] Error: Log file not found.")

if __name__ == "__main__":
    hunt_lolbins("dummy_logs.json")
