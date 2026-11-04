# soc-home-lab

A personal, hands-on Security Operations Center (SOC) home lab, built to practice
blue-team skills: log analysis, threat detection, SIEM engineering, and incident
reporting. This repository documents the projects and investigations produced in
that lab.

> All attack activity in this lab is self-generated against systems I own, in an
> isolated environment, for training purposes only.

---

## Lab Environment

| Host | Role |
|---|---|
| **Ubuntu Server** | Target host and SIEM server (Splunk Enterprise) |
| **Kali Linux** | Attacker machine (offensive tooling) |
| **Windows 10** | Endpoint for Windows Event Log analysis |

All hosts run as virtual machines (VirtualBox) on an isolated lab network. Splunk
was installed and configured from scratch on the Ubuntu host, with Linux
authentication logs ingested for analysis and detection.

---

## Projects

| Project | Description |
|---|---|
| [SSH Brute-Force Investigation](./SSH_Bruteforce_Investigation.md) | Full investigation of an automated SSH brute-force attack: detection in Splunk, timeline, impact analysis, and remediation recommendations. |
| [Threat Hunt — SSH Brute-Force Against admin](./Threat_Hunt_SSH_Admin_Bruteforce.md) | A threat hunt triggered by a server performance alert: scoped a failed SSH brute-force attack in Splunk, confirmed no compromise, and identified the server's rate-limiting as the root cause. |
| [Incident — SSH Compromise with Root Access](./Incident_SSH_Compromise_Root_Access.md) | Investigation of a successful SSH brute-force that escalated to root via sudo and exfiltrated /etc/shadow. Covers detection, post-compromise command tracing, persistence check, and containment. |
| [Incident — Windows RDP Brute-Force](./Incident_Windows_RDP_Bruteforce.md) | Investigation of an RDP brute-force attempt against a Windows host, using Event Viewer (4625/4624). Covers Windows logon artifacts (SubStatus, LogonType, WorkstationName), failure confirmation, and MITRE mapping. |
| [Network Analysis — SSH Brute-Force (PCAP)](./Network_Analysis_SSH_Bruteforce_PCAP.md) | Packet-level analysis of an SSH brute-force in Wireshark using only traffic metadata. Covers a top-down methodology (Conversations, Follow Stream, SYN counting), inferring success from session size on encrypted traffic, and MITRE mapping. |

---

## Skills Practiced

- **Linux log analysis** — `grep`, `awk`, `sort`, `uniq`, reading `/var/log/auth.log`
- **Network traffic analysis** — Wireshark, PCAP analysis, TCP 3-way handshake, Conversations & Protocol Hierarchy, DNS, HTTP
- **Windows Event Logs** — logon events (4624/4625), Logon Types, SubStatus codes, baselining
- **SIEM engineering** — installing and configuring Splunk, data ingestion, source types
- **Detection engineering** — writing SPL queries, extracting fields with `rex`,
  building detection rules and scheduled alerts, tuning thresholds (false positives
  vs. false negatives)
- **Threat frameworks** — mapping investigations to MITRE ATT&CK tactics and techniques
- **Incident reporting** — structured investigation reports separating facts from
  hypotheses

---

## Planned / In Progress

- [ ] Detection rules collection (documented SPL queries)
- [ ] Threat hunting hypothesis & report
- [ ] Windows Sysmon logging and detection

---

*This lab is an ongoing learning project. Each completed investigation is added above
as its own documented case.*
