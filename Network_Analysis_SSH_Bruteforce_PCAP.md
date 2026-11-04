# Network Analysis — SSH Brute-Force (PCAP)

**Analyst:** Salem Awad Alshehri
**Date of Report:** 4 November 2026
**Environment:** Personal SOC home lab (Ubuntu Server + Kali Linux + Wireshark)
**Classification:** Training / Portfolio project

> This analysis was performed in a self-owned, isolated lab. All traffic was
> self-generated and authorized, for training purposes only.

---

## 1. Executive Summary

A packet capture (PCAP) of SSH traffic was analyzed in Wireshark to investigate a
brute-force attack at the **network layer** — using only packet metadata, without
access to host logs. The capture showed an attack from `192.168.1.223` against the
SSH service (port 22) of `192.168.1.221`: **6 connection attempts** (brute-force
guesses) followed by **one long, successful session** (510 packets). Although the
SSH payload is encrypted, the attack's behavior and outcome were fully reconstructed
from traffic metadata.

---

## 2. Methodology

The capture was analyzed top-down, letting the data guide the investigation rather
than assuming the attack type in advance:

1. **Statistics → Conversations (IPv4):** identified the dominant conversation —
   `192.168.1.223 ↔ 192.168.1.221` with 641 packets, standing out against all other
   traffic (≤6 packets). This flagged the pair of interest without prior assumptions.
2. **Follow TCP Stream:** confirmed the payload is encrypted (unreadable), as expected
   for SSH.
3. **SYN filter** (`tcp.port == 22 && tcp.flags.syn == 1 && tcp.flags.ack == 0`):
   counted new connection attempts.
4. **Per-connection TCP conversations:** isolated the single long-lived session,
   indicating a successful login.

---

## 3. Findings

| Finding | Value | Evidence |
|---|---|---|
| Attacker | `192.168.1.223` | Dominant conversation source |
| Target | `192.168.1.221` | Conversation destination |
| Service | SSH (TCP port 22) | Destination port of all attack packets |
| Failed attempts | 6 | Count of SYN packets (new connections) |
| Successful session | 1 (≈510 packets) | A single long TCP stream, far larger than the short failed attempts |
| Attacker SSH version | OpenSSH 10.2p1 (Debian) | Cleartext protocol banner before encryption |
| Target SSH version | OpenSSH 10.2p1 (Ubuntu) | Cleartext protocol banner before encryption |

### How success/failure was inferred (encrypted traffic)
- **Failed attempts:** short connections, few packets, closed quickly.
- **Successful login:** one connection with a large packet count (≈510), consistent
  with an interactive session where activity occurred after authentication.

---

## 4. Analysis

- Multiple short SSH connections from a single source in quick succession is the
  classic network signature of an automated brute-force tool. The content is
  encrypted, but the **pattern** (repeated rapid connection attempts) is unmistakable.
- The SSH version banners are exchanged **before** encryption begins, so they are
  visible in the capture. This leaks the OS/software versions of both hosts — useful
  reconnaissance an attacker could use to target version-specific vulnerabilities.
- The long session confirms the brute force eventually **succeeded**: the attacker
  established an authenticated session.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |
| Initial Access | Valid Accounts (via guessed credentials) | T1078 |

---

## 6. Recommendations

1. Disable SSH password authentication; enforce key-based authentication.
2. Deploy fail2ban / rate-limiting to block repeated connection attempts.
3. Monitor for many short-lived SSH connections from a single source in a short
   window — a network-level brute-force indicator that works even on encrypted traffic.
4. Restrict SSH exposure (VPN, allow-list source IPs).

---

## 7. Notes & Limitations

- SSH payload is encrypted; the **content** of the sessions (commands, credentials
  tried) cannot be recovered from the PCAP. Findings are based on metadata only.
- Success is **inferred** from session length, not read directly; correlating with
  host auth logs would confirm it definitively.
- Version banners can, in principle, be altered by either host.
- All analysis was performed on a saved PCAP, independent of the live hosts.
