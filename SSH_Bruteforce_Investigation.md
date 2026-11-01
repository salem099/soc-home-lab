# SSH Brute-Force Attack — Investigation Report

**Analyst:** Salem Awad Alshehri
**Date of Report:** 1 November 2026
**Environment:** Personal SOC home lab (Ubuntu Server + Kali Linux + Splunk Enterprise)
**Classification:** Training / Portfolio project

> This investigation was performed in a self-owned, isolated lab environment for
> training purposes. All attack activity was authorized and self-generated.

---

## 1. Executive Summary

On 31 October 2026, at approximately **12:50 UTC**, a brute-force attack was detected
against the **SSH service (port 22)** of host `ubuntu`. The attack originated from the
internal lab host `192.168.1.25` (Kali Linux). **Seven failed login attempts** were
recorded against the user `ubuntu` within **0.69 seconds**, indicating the use of an
automated tool rather than manual entry. The attack ultimately **succeeded**, and valid
credentials for the `ubuntu` account were obtained.

**Severity: High** — the attack resulted in successful authentication to an account
that holds `sudo` privileges.

---

## 2. Timeline of Events (UTC)

| Time (UTC) | Event | Evidence | Type |
|---|---|---|---|
| 12:50:14 | 7 failed SSH login attempts against user `ubuntu` from `192.168.1.25` | Splunk: `Failed password` events (count = 7) | Fact |
| 12:50:14 | All attempts occurred within 0.69 seconds, indicating automated tooling | Splunk: `max(_time) - min(_time)` = 0.69s | Fact |
| ~12:50:15 | Successful login; valid credentials for `ubuntu` obtained | hydra output (`Accepted password` in Splunk — *pending verification*) | Fact |
| Post-login | Attacker may have accessed or exfiltrated data | No supporting evidence | Hypothesis |

---

## 3. Impact

**Confirmed:**
The attacker obtained valid credentials for user `ubuntu` and successfully
authenticated via SSH.

**Potential (High):**
The `ubuntu` account holds `sudo` privileges, so the attacker could escalate to
root. This would enable persistence, backdoor installation, lateral movement, or
data exfiltration.

**Unknown:**
No evidence of post-login activity was found. The attacker's intent and subsequent
actions are unconfirmed and require deeper investigation (command history, new user
accounts, scheduled tasks, outbound network connections).

---

## 4. Detection

The attack was detected in Splunk using the following SPL query, which extracts the
source IP from failed SSH logins and flags any IP exceeding a threshold of failed
attempts:

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\S+) port"
| stats count by src_ip
| where count >= 5
```

This query was saved as a scheduled alert (**"SSH Brute Force"**) that runs hourly and
triggers when any source IP reaches 5 or more failed logins.

---

## 5. Recommendations

### Immediate (Containment)
1. Disable/lock the `ubuntu` account, reset its password, and terminate any active
   attacker sessions.
2. Investigate the host for post-compromise activity: new users, cron jobs, outbound
   connections, and command history.

### Preventive
3. **Disable SSH password authentication and enforce SSH key-based authentication.**
   This makes brute-force attacks ineffective, as there is no password to guess.
4. **Deploy fail2ban** to automatically block source IPs after repeated failed logins
   within a short time window (rate limiting).
5. Enforce strong password and MFA policies.
6. Conduct security-awareness training for users.

---

## 6. Notes & Limitations

- The `Accepted password` event in Splunk is pending direct verification; the success
  of the attack is currently evidenced by the hydra output.
- No post-login activity was observed in the available logs; absence of evidence is
  not evidence of absence.
- All timestamps are reported in UTC. The source host (Kali) displayed times in local
  time, which were normalized to UTC for this report.
