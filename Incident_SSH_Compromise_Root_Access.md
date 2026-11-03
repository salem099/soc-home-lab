# Incident Report — Successful SSH Compromise with Root Access

**Analyst:** Salem Awad Alshehri
**Date of Report:** 3 November 2026
**Environment:** Personal SOC home lab (Ubuntu Server + Kali Linux + Splunk Enterprise)
**Classification:** Training / Portfolio project

> This incident was investigated in a self-owned, isolated lab. All attack activity
> was self-generated and authorized, for training purposes only.

---

## 1. Trigger

The "SSH Brute Force" scheduled alert (previously built in Splunk) fired for host
`192.168.8.23`. The alert was escalated for investigation to determine whether the
attack succeeded and what actions, if any, the attacker took.

---

## 2. Executive Summary

On 2 November 2026, an SSH brute-force attack from source `192.168.8.19`
**succeeded** against the `ubuntu` account on host `192.168.8.23`. After five failed
password attempts, the attacker authenticated successfully (two logins at
**02:01:58** and **02:02:24 UTC**). The attacker then used **`sudo` to escalate to
root** and read **`/etc/shadow`**, exfiltrating the password hashes of all system
accounts.

**Severity: Critical** — confirmed compromise, privilege escalation to root, and
credential theft affecting every account on the host.

---

## 3. Timeline of Events (UTC)

| Time (UTC) | Event | Evidence | Type |
|---|---|---|---|
| (prior to 02:01) | 5 failed SSH login attempts against `ubuntu` from `192.168.8.19` | Splunk: `Failed` events (count = 5) | Fact |
| 02:01:58 | First successful SSH login to `ubuntu` from `192.168.8.19` | Splunk: `Accepted password` | Fact |
| 02:02:24 | Second successful SSH login (≈26s later) | Splunk: `Accepted password` | Fact |
| 02:02:49 | `sudo` used to run `cat /etc/shadow` as root | Splunk: `COMMAND=/usr/bin/cat /etc/shadow`, `USER=root` | Fact |
| 02:02:49 | `sudo` used to run `whoami` as root | Splunk: `COMMAND=/usr/bin/whoami`, `USER=root` | Fact |
| — | Attack preceded by brute force; pattern suggests automated tooling | Failed-then-success pattern | Hypothesis |

---

## 4. Analysis

- **Source:** `192.168.8.19` — single IP, consistent with a focused attack.
- **Method:** password brute-force (5 failed attempts), immediately followed by
  successful login. This failed-then-success pattern **strongly suggests** an
  automated brute-force tool, though the tool itself is not identifiable from the logs.
- **Compromise confirmed:** two `Accepted password` events for `ubuntu` from the
  attacker IP. This is a confirmed intrusion, not a failed attempt.
- **Privilege escalation:** the `ubuntu` account holds `sudo` rights. The attacker
  used `sudo` to execute commands as **root** (`USER=root`, `uid=0`).
- **Impact action — credential access:** the attacker ran `cat /etc/shadow`, reading
  the hashed passwords of every account on the system. These hashes can be cracked
  offline, placing **all accounts on the host at risk**, not only `ubuntu`.
- **Persistence check:** no new user or group was created within the attack window.
  (A `useradd`/`groupadd` for `splunk` exists in the logs but dates to 27 Oct — the
  Splunk installation — not the attack.)

---

## 5. Detection

Scoping the brute force and confirming success:

```spl
index=main sourcetype=linux_secure "Failed"
| rex "from (?<src_ip>\S+) port"
| stats count by src_ip

index=main sourcetype=linux_secure "Accepted" "192.168.8.19"
```

Identifying post-compromise commands:

```spl
index=main sourcetype=linux_secure "COMMAND="
| rex "COMMAND=(?<command>.*)"
| table _time command
```

Persistence check (new accounts):

```spl
index=main sourcetype=linux_secure "useradd" OR "adduser" OR "new user" OR "new group"
```

---

## 6. Recommendations

### Immediate (Containment)
1. Isolate host `192.168.8.23` from the network (do not power off — preserve volatile
   evidence).
2. Treat **all** account credentials on the host as compromised. Force a password
   reset for every account, since `/etc/shadow` was exfiltrated.
3. Disable/lock the `ubuntu` account and terminate any active attacker sessions.
4. Investigate for further persistence (cron jobs, SSH keys, modified services).

### Preventive
5. Disable SSH password authentication; enforce key-based authentication.
6. Deploy fail2ban / rate-limiting to block repeated failed logins.
7. Review and restrict `sudo` privileges (principle of least privilege).
8. Enforce strong, unique passwords and MFA.

---

## 7. Notes & Limitations

- **Data integrity:** during the investigation, Splunk reported a corrupted data
  bucket ("Results may be incomplete"), likely caused by an unclean shutdown. Some
  events may therefore be missing, and findings are based on the available data.
- A preceding port scan is plausible but was not confirmed from `auth.log` (host
  authentication logs do not record port scans).
- The brute-force tool is inferred from the access pattern, not directly evidenced.
- All timestamps are in UTC.
