# Threat Hunt — SSH Brute-Force Against `admin`

**Analyst:** Salem Awad Alshehri
**Date of Report:** 2 November 2026
**Environment:** Personal SOC home lab (Ubuntu Server + Kali Linux + Splunk Enterprise)
**Classification:** Training / Portfolio project

> This hunt was performed in a self-owned, isolated lab. All activity was
> self-generated and authorized, for training purposes only.

---

## 1. Trigger

The operations team reported that the server `192.168.1.221` became briefly
unresponsive during the night. No further detail was provided. A threat hunt was
initiated to determine whether malicious activity was responsible.

---

## 2. Executive Summary

On 1 November 2026, between **03:25:37 and 03:25:46 UTC**, an automated SSH
brute-force attack was carried out against host `192.168.1.221` from the source
host `192.168.1.25`. The attack targeted the user **`admin`** with **8 failed
password attempts** (10 failed SSH events in total from the source) over a span of
**9 seconds**, confirming automated tooling.

**The attack failed.** No successful authentication (`Accepted password`) from the
source IP was found. The server's built-in SSH rate-limiting activated automatically,
penalizing the source IP and dropping its connections — which also explains the brief
unresponsiveness reported by the operations team.

**Severity: Low** — the attack was unsuccessful and was mitigated by existing controls.

---

## 3. Timeline of Events (UTC)

| Time (UTC) | Event | Evidence | Type |
|---|---|---|---|
| ~03:25 (prior) | Suspected port scan of the host | Not confirmed in `auth.log` — see Limitations | Hypothesis |
| 03:25:37 | First failed SSH login against `admin` from `192.168.1.25` | Splunk: `min(_time)` | Fact |
| 03:25:37–03:25:46 | 8 failed password attempts against `admin`; 10 failed SSH events total | Splunk: `stats count` | Fact |
| 03:25:4x | Server activated rate-limiting; connections dropped | Splunk: `srclimit_penalise`, `drop connection` events | Fact |
| 03:25:46 | Last failed attempt | Splunk: `max(_time)` | Fact |
| — | No successful login from the source IP | Splunk: 0 `Accepted` events from `192.168.1.25` | Fact |

**Duration:** ~9 seconds for 10 attempts → automated, not human.

---

## 4. Analysis

- **Source:** `192.168.1.25` (single IP — a focused, deliberate attack, not scattered noise).
- **Target:** the `admin` account over SSH (port 22).
- **Method:** automated password brute-force (10 attempts in 9 seconds).
- **Outcome:** failed. Every authentication event was a failure; no `Accepted`
  event exists for the source IP. Because the attacker never logged in, no
  post-compromise commands were possible or observed.
- **Server response:** OpenSSH's `srclimit` / per-source rate-limiting triggered
  automatically, penalizing the IP and dropping further connections. This is the
  likely cause of the short unresponsiveness the operations team noticed.

---

## 5. Detection

The failed activity was identified and scoped in Splunk using SPL:

```spl
index=main sourcetype=linux_secure "Failed"
| rex "for (?:invalid user )?(?<user>\S+) from"
| stats count by user
```

Verification that the attack did not succeed:

```spl
index=main sourcetype=linux_secure "Accepted" "192.168.1.25"
```
(Result: 0 events.)

Time-scoping of the attack:

```spl
index=main sourcetype=linux_secure "Failed" "192.168.1.25"
| stats count min(_time) as first max(_time) as last
| convert ctime(first) ctime(last)
```

---

## 6. Recommendations

1. Confirm that SSH rate-limiting / `fail2ban` is in place and tuned (it worked here).
2. Disable SSH password authentication; enforce key-based authentication to make
   brute-force attacks ineffective.
3. Ensure the `admin` account uses a strong, unique password (and ideally does not
   permit direct remote login).
4. Add network-layer logging (firewall / packet capture) to detect reconnaissance
   such as port scans, which host logs alone cannot see.

---

## 7. Notes & Limitations

- A port scan (e.g. `nmap`) is suspected to have preceded the brute-force, but it
  could **not** be confirmed from `auth.log`. Port scans do not generate
  authentication events; confirming this requires network or firewall logs.
- All timestamps are in UTC.
- This hunt relied solely on SSH authentication logs. A complete picture would
  correlate host logs with network traffic and firewall data.
- "Absence of evidence is not evidence of absence": no post-login activity was found
  because the attacker never authenticated successfully.
