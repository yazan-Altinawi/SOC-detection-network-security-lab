# SOC Detection & Network Security Analysis Lab

Hands-on security lab focused on Windows authentication telemetry, SIEM detection, packet analysis, firewall controls, and IDS/IPS fundamentals.

## What I worked with

- Windows Security Event IDs 4624, 4625, and 4648
- Local vs network logon analysis using logon type and source address
- Splunk ingestion, filtering, correlation, and alert creation
- Detection of repeated failed logins followed by successful authentication
- HTTP vs HTTPS/TLS analysis in Wireshark
- TCP three-way handshake and TLS negotiation
- Windows Defender Firewall rule testing
- Controlled Nmap port-scan traffic and IDS/IPS detection concepts

## Detection Logic

The Splunk detection looks for at least three failed logons followed by at least one successful logon from the same source within a short time window.

```spl
index=* source="WinEventLog:Security" earliest=-5m (EventCode=4625 OR EventCode=4624)
| eval Target_Account=mvindex(Account_Name,-1)
| stats count(eval(EventCode=4625)) AS Failed_Logins count(eval(EventCode=4624)) AS Successful_Logins by Target_Account Source_Network_Address
| where Failed_Logins>=3 AND Successful_Logins>=1
```

## Files

- `SOC_Detection_Network_Security_Analysis_Lab_Report.pdf` - concise technical report
- `splunk-authentication-timeline.png` - SIEM investigation evidence
- `wireshark-http-request.png` - readable HTTP request captured before TLS encryption
