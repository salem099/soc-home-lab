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
---

## Skills Practiced

- **Linux log analysis** — `grep`, `awk`, `sort`, `uniq`, reading `/var/log/auth.log`
- **Network traffic analysis** — Wireshark, TCP 3-way handshake, DNS, HTTP
- **Windows Event Logs** — logon events (4624/4625), Logon Types, baselining
- **SIEM engineering** — installing and configuring Splunk, data ingestion, source types
- **Detection engineering** — writing SPL queries, extracting fields with `rex`,
  building detection rules and scheduled alerts, tuning thresholds (false positives
  vs. false negatives)
- **Incident reporting** — structured investigation reports separating facts from
  hypotheses

---

## Planned / In Progress

- [ ] Windows Event Log investigation write-up (logon analysis)
- [ ] Network traffic analysis case (PCAP walkthrough)
- [ ] Detection rules collection (documented SPL queries)
- [ ] Threat hunting hypothesis & report

---

*This lab is an ongoing learning project. Each completed investigation is added above
as its own documented case.*
