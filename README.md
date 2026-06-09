# Adversary Emulation & Detection Lab

**Student:** Azmul Hosen Titu  
**Roll:** 60027  
**Platform:** VirtualBox Host-Only Network Deployment  
**SIEM:** Splunk Enterprise on Kali Linux  
**Endpoint:** Windows Server 2019 with Sysmon Telemetry

## Project Overview

This repository documents an isolated blue-team lab for adversary emulation and detection engineering. The lab uses Kali Linux as the control/SIEM node and Windows Server 2019 as the victim telemetry endpoint. Atomic Red Team tests are executed on the Windows host, logs are collected by Sysmon, forwarded with Splunk Universal Forwarder, and analyzed in Splunk Enterprise.

## Lab Architecture

| Component | Role | IP / Port |
|---|---|---|
| Kali Linux | Splunk Enterprise SIEM / Control Node | 192.168.56.101 |
| Windows Server 2019 | Victim / Telemetry Node | 192.168.56.110 |
| Splunk Receiving Port | Forwarder log ingestion | 9997 |
| Splunk Web UI | Search and dashboard | 8000 |

The topology is based on a host-only VirtualBox network so that the lab remains isolated from production networks.

## Repository Structure

```text
.
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   └── Adversary_Emulation_Detection_Lab_Report.docx
├── screenshots/
│   └── screenshot-*.png/jpeg
├── configs/
│   ├── inputs.conf
│   └── sysmonconfig.xml
└── splunk_queries/
    ├── T1053_005_Scheduled_Task.spl
    ├── T1218_005_MSHTA.spl
    ├── T1003_001_LSASS_ProcDump.spl
    ├── T1059_001_PowerShell_Download.spl
    └── T1112_Registry_Modification.spl
```

## Infrastructure Setup

| Virtual Machine | CPU | RAM | Network Adapter |
|---|---:|---:|---|
| Kali Linux Control Node | 2 cores | 4 GB minimum | Host-Only / NAT Shared |
| Windows Server 2019 Telemetry Victim | 2 cores | 4 GB minimum | Host-Only / NAT Shared |

## Splunk Enterprise Deployment

Splunk Enterprise was installed on Kali Linux and configured as the central log ingestion and analysis platform.

Receiver configuration:

```bash
./splunk enable listen 9997 -auth admin:password
```

## Splunk Universal Forwarder Setup

Splunk Universal Forwarder was installed on Windows Server 2019 and configured to send logs to the Splunk server:

```text
Receiving Indexer: 192.168.56.101:9997
```

## Sysmon Setup

Sysmon was installed on the Windows endpoint to capture process creation, registry activity, process access, and other host telemetry.

```powershell
sysmon64.exe -i sysmonconfig.xml -accepteula
```

Forwarder input configuration:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
renderXml = true
index = main
```

## Atomic Red Team Setup

Invoke-AtomicRedTeam was used to emulate adversary behavior safely inside the lab.

```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
$global:PathToAtomicsFolder = "C:\AtomicRedTeam\atomics"
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```

## MITRE ATT&CK Detection Coverage

| Technique ID | Technique | Tactic | Atomic Test | Detection Source |
|---|---|---|---|---|
| T1053.005 | Scheduled Task | Persistence | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | Sysmon Event ID 1 |
| T1218.005 | MSHTA | Defense Evasion | `Invoke-AtomicTest T1218.005 -TestNumbers 1` | Sysmon Event ID 1 |
| T1003.001 | LSASS Dumping via ProcDump | Credential Access | `Invoke-AtomicTest T1003.001 -TestNumbers 1` | Sysmon Event ID 1 / Event ID 10 |
| T1059.001 | PowerShell | Execution | `Invoke-AtomicTest T1059.001 -TestNumbers 1` | Sysmon Event ID 1 |
| T1112 | Registry Modification | Defense Evasion / Persistence | `Invoke-AtomicTest T1112 -TestNumbers 2` | Sysmon Event ID 1 / Event ID 13 |

## Detection Queries

All SPL queries are stored in the [`splunk_queries`](splunk_queries/) folder.

### T1053.005 - Scheduled Task

Detects `schtasks.exe` process creation used to create scheduled tasks.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "schtasks.exe"
| rex field=_raw "<EventID>(?<Event_ID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Process_Name>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<Command_Line>[^<]+)</Data>"
| search Event_ID=1
| table _time, host, Event_ID, Process_Name, Command_Line
```

### T1218.005 - MSHTA Execution

Detects `mshta.exe` LOLBIN execution.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "mshta.exe"
| rex field=_raw "<EventID>(?<Event_ID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Process_Name>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<Command_Line>[^<]+)</Data>"
| search Event_ID=1
| table _time, host, Event_ID, Process_Name, Command_Line
```

### T1003.001 - LSASS Dumping via ProcDump

Detects ProcDump execution related to LSASS dumping.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "procdump"
| rex field=_raw "<EventID>(?<Event_ID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Process_Name>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<Command_Line>[^<]+)</Data>"
| search Event_ID=1
| table _time, host, Event_ID, Process_Name, Command_Line
```

### T1059.001 - PowerShell Download Activity

Detects suspicious PowerShell download cradles.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "powershell.exe"
| rex field=_raw "<EventID>(?<Event_ID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Process_Name>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<Command_Line>[^<]+)</Data>"
| search Event_ID=1 (Command_Line="*DownloadString*" OR Command_Line="*Invoke-WebRequest*" OR Command_Line="*iwr*")
| table _time, host, Event_ID, Process_Name, Command_Line
```

### T1112 - Registry Modification

Detects registry modification through `reg.exe`.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "reg.exe"
| rex field=_raw "<EventID>(?<Event_ID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Process_Name>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<Command_Line>[^<]+)</Data>"
| search Event_ID=1
| table _time, host, Event_ID, Process_Name, Command_Line
```

## Key Findings

- Sysmon Event ID 1 was the primary data source for process creation visibility.
- Scheduled task creation was detected through `schtasks.exe` command-line telemetry.
- MSHTA abuse was detected through `mshta.exe` execution and inline JavaScript indicators.
- ProcDump activity was detected by looking for `procdump` execution and LSASS-related command arguments.
- PowerShell download activity was detected through suspicious command-line strings such as `DownloadString`, `Invoke-WebRequest`, and `iwr`.
- Registry modification activity was detected through `reg.exe` command-line execution.

## Lessons Learned

This project demonstrates how adversary emulation can be combined with endpoint telemetry and SIEM analysis to build practical blue-team detection logic. It also shows the importance of command-line logging, Sysmon configuration, and mapping detections to MITRE ATT&CK techniques.

## Disclaimer

This project is for academic and defensive cybersecurity learning only. All tests should be performed only in an isolated lab environment that you own or have permission to use.
