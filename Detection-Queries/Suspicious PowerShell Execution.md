Suspicious PowerShell Execution Detection

1. Objective

Detect potentially malicious PowerShell activity that may indicate script execution, defense evasion, or malware download attempts.

2. MITRE ATT&CK Mapping

* Technique: T1059.001
* Name: PowerShell
* Tactic: Execution

3. Suspicious Indicators

Look for:

* Encoded PowerShell commands.
* Hidden or non-interactive execution.
* Execution policy bypass.
* DownloadString or Invoke-WebRequest.
* PowerShell launched by unusual parent processes.

4. Detection Query (Microsoft Defender KQL)
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
    or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any (
    "-enc",
    "-encodedcommand",
    "-executionpolicy bypass",
    "-windowstyle hidden",
    "downloadstring",
    "invoke-webrequest",
    "frombase64string"
)
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp desc
```

## 5. Triage and Investigation

- Review the complete PowerShell command line.
- Identify the user account and affected device.
- Examine the parent process.
- Check for suspicious network connections.
- Review related process activity and downloaded files.
- Escalate confirmed malicious activity.

## 6. Mitigation and Remediation

- Isolate confirmed compromised devices.
- Disable or reset compromised accounts where necessary.
- Remove malicious scripts and persistence mechanisms.
- Block confirmed malicious domains and IP addresses.
- Preserve logs and evidence for further investigation.

## 7. References

- MITRE ATT&CK: T1059.001 – PowerShell
- Microsoft Defender: DeviceProcessEvents
