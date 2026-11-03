# Incident Report — Windows RDP Brute-Force Attempt

**Analyst:** Salem Awad Alshehri
**Date of Report:** 3 November 2026
**Environment:** Personal SOC home lab (Windows 10 + Kali Linux + VirtualBox)
**Classification:** Training / Portfolio project

> This incident was investigated in a self-owned, isolated lab. All attack activity
> was self-generated and authorized, for training purposes only.

---

## 1. Executive Summary

On 3 November 2026, at approximately **13:38 UTC**, a brute-force attack was carried
out against the Remote Desktop (RDP) service of the Windows host `DESKTOP-HOF741E`.
The attack originated from `192.168.1.223` (workstation name: **kali**) and targeted
the existing account **`Windows`** with **7 failed logon attempts within ~4 seconds**,
indicating automated tooling.

**The attack failed.** Every attempt was recorded as a failed logon (Event ID 4625)
with sub-status `0xC000006A` (bad password), and **no successful logon (Event ID
4624)** originated from the attacker's IP.

**Severity: Medium** — the attack was unsuccessful, but it targeted a valid account
over an exposed remote-access service.

---

## 2. Timeline of Events (UTC)

| Time (UTC) | Event | Evidence | Type |
|---|---|---|---|
| 13:38:21–13:38:25 | 7 failed logon attempts against account `Windows` from `192.168.1.223` | Event ID 4625 (x7) | Fact |
| 13:38:21–13:38:25 | All attempts within ~4 seconds → automated tooling | Timestamps of 4625 events | Fact |
| — | No successful logon from the attacker IP | No Event ID 4624 from `192.168.1.223` | Fact |
| — | Attack pattern consistent with an automated brute-force tool | Rapid, repeated failures from one source | Hypothesis |

---

## 3. Analysis

- **Source:** `192.168.1.223`, workstation name **`kali`** — a strong indicator of an
  attack tool, as legitimate workstations rarely carry that name.
- **Target:** the `Windows` account, which **exists** on the host (confirmed by
  sub-status `0xC000006A` = *bad password*, not `0xC0000064` = *user not found*).
  Targeting a valid account raises the risk.
- **Method:** RDP brute-force. Logged as **Logon Type 3 (Network)** using **NTLM**,
  because the tool authenticated at the network layer before establishing a full RDP
  session.
- **Outcome:** failed. Confirmed by two independent indicators: every 4625 shows a
  bad-password sub-status, and no 4624 (successful logon) exists from the attacker IP.

### Key Windows artifacts referenced
- **Event ID 4625** — an account failed to log on.
- **SubStatus `0xC000006A`** — bad password (account exists).
- **LogonType 3** — network logon.
- **WorkstationName** / **IpAddress** — attacker identity.

---

## 4. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Initial Access / Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 |

---

## 5. Detection

Investigation was performed in Windows Event Viewer (Security log), filtering by
Event ID:

- **Failed logons:** filter `Event ID = 4625`, inspect `IpAddress`,
  `TargetUserName`, `WorkstationName`, `LogonType`, and `SubStatus`.
- **Verify success/failure:** filter `Event ID = 4624` and check for any logon from
  the attacker IP (`192.168.1.223`). None found → attack failed.

A detection rule for this would alert on a threshold of 4625 events from a single
source IP within a short time window (e.g. 5+ in 1 minute).

---

## 6. Recommendations

### Immediate
1. Confirm the `Windows` account password is strong and unique; reset if in doubt.
2. Block the source IP `192.168.1.223` at the firewall.

### Preventive
3. **Do not expose RDP directly.** Restrict it to a VPN, or disable it if not needed.
4. Enable an **account lockout policy** (lock after N failed attempts) to defeat
   brute force.
5. Enforce **Network Level Authentication (NLA)** for RDP.
6. Enable MFA for remote access where possible.
7. Alert on repeated 4625 events from a single source (as above).

---

## 7. Notes & Limitations

- The brute-force tool is inferred from the access pattern (rapid repeated failures),
  not directly evidenced in the logs.
- The attacker's workstation name (`kali`) was recorded, but such fields can be
  spoofed and should not be relied on alone.
- All timestamps are in UTC.
- This investigation relied on Windows Security event logs only; correlating with
  network logs would provide a fuller picture.
