# LOLBins Threat Hunting Parser

### Overview
Adversaries frequently use "Living Off The Land Binaries" (LOLBins)—legitimate Windows tools—to download malware or bypass security controls without dropping custom executables. 

This project is a lightweight Python detection engine that parses JSON-formatted Endpoint Detection (EDR) or Windows Event Logs (Event ID 4688) to detect malicious command-line arguments associated with LOLBins.

### Threat Focus (MITRE ATT&CK)
* **T1105: Ingress Tool Transfer** (via `certutil.exe` and `bitsadmin.exe`)
* **T1059.001: PowerShell** (via Base64 `-enc` obfuscation)

### Usage
This repository includes a `dummy_logs.json` file representing standardized SIEM telemetry. 

To run the hunt:
```bash
python3 lolbins_hunter.py
