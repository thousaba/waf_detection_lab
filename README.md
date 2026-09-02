# WAF Detection Lab

A home lab project that deploys a real Web Application Firewall (ModSecurity + OWASP CRS) in front of a deliberately vulnerable internal web application ("Meridian Corp"), generates realistic attack and user traffic against it, and forwards everything into Splunk for detection engineering work — coverage testing, correlation searches, alerting, and (eventually) automated response.

The goal isn't just "stand up a WAF" — it's to work through the full lifecycle a real detection engineer deals with: deploy → verify it's actually protecting anything → find what it misses → build detection and logging to cover the gaps → alert on it.

---

## Why this exists

This project is part of a broader home detection lab focused on blue-team / detection engineering skills (Splunk, MITRE ATT&CK, Active Directory security, network security monitoring). Most WAF write-ups stop at "I installed ModSecurity and it blocked an SQLi payload." This one goes further: a proper coverage baseline against a real target uncovered that the WAF wasn't blocking *anything* (misconfigured in detection-only mode), and that even once fixed, entire vulnerability classes (IDOR, brute force) pass straight through because they're invisible to signature-based rules — which is a far more realistic and useful thing to have found and fixed.

---

## Architecture

```
        Kali (attacker + normal-traffic simulation)
                    │
                    ▼
   Nginx + ModSecurity + OWASP CRS   (WSL2, Ubuntu)
                    │  proxy_pass
                    ▼
   Meridian Corp — Flask + PostgreSQL app (WSL2)
   (fake internal HR/SaaS panel: employees, customers, login)
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
 modsec_audit.log       meridian_security.log
        │                       │
        └───────┬───────────────┘
                 ▼
   Splunk Universal Forwarder (WSL2)
                 │  :9997
                 ▼
   Splunk Enterprise (native Windows host)
   indexes: web_modsec, web_app_security
```

- **WAF**: Nginx + ModSecurity 3.x, OWASP Core Rule Set 4.30.0-dev, running in WSL2 on the same host as the rest of the lab.
- **Target application**: Meridian Corp — a single-file Flask + PostgreSQL app simulating an internal HR/SaaS panel (employee records, customer accounts, login). Seeded with synthetic data only. Contains four intentional vulnerabilities (SQLi, stored XSS, IDOR, weak auth) so attack traffic has real sinks to hit instead of an empty page.
- **Log pipeline**: Splunk Universal Forwarder (WSL2) → Splunk Enterprise (native Windows host) over the standard S2S port (9997). Two indexes: `web_modsec` (WAF audit log) and `web_app_security` (app-level auth/access events the WAF can't see).
- **Traffic generation**: a Python script simulating a mix of normal browsing traffic and periodic attacker bursts (SQLi, XSS, LFI, RCE, SSRF) against the target, and a separate session-aware coverage script that logs in and tests each vulnerability class directly.

---

## What's been done so far

### Setup & Foundation

1. **WAF + Splunk pipeline setup** — deployed ModSecurity/CRS, connected the WSL2 forwarder to the Windows-side Splunk indexer, and debugged a stuck output pipeline (a stale, unrelated monitor input pointed at a non-existent index was silently blocking the entire shared TCP output queue). Fixed ModSecurity's multi-part audit log format with a custom `LINE_BREAKER` so each transaction indexes as one Splunk event.
   → [`01-waf-setup-and-troubleshooting.md`](./docs/1-Building%20WAF.md)
2. **Built a realistic target** — replaced the default Nginx welcome page with Meridian Corp, a Flask/SQLite app with synthetic employee/customer data and deliberately built vulnerabilities, so attack traffic has something real to succeed or fail against.
   → [`02-meridian-corp-architecture.md`](./docs/2-Building%20A%20Realistic%20Target.md)
3. **Baseline coverage testing** — found ModSecurity was running in `DetectionOnly` (logging everything, blocking nothing); after fixing that, SQLi/XSS were fully blocked but IDOR and brute force passed through untouched and weren't even visible in the WAF's own audit log. Added structured application-level security logging to close that gap.
   → [`03-waf-blindspots-and-app-logging.md`](./docs/3-Baseline%20Testing.md)

### IDOR & Access Control Chain

[IDOR Lab](./docs/4-IDOR.md)

4. **Read-path IDOR** — detected via a Splunk correlation search (low-privilege user viewing an unusual number of distinct employee records), fixed with a role check, verified via manual reproduction and a second detection confirming denied attempts.
5. **Session forgery bypass** — found the read-path fix was fully bypassable: a hardcoded Flask `secret_key` let anyone forge a validly-signed `role=admin` session with no login required. Fixed by generating the key randomly at runtime.
6. **Write-path IDOR** — the same role check had never been applied to the notes-adding endpoint; fixed, and noted it compounds with a stored-XSS sink in the same field (widening who an XSS payload could reach).
7. **Completing the detection layer** — built Splunk detections for the two prior fixes, contrasting positive detections (event-driven) with negative/correlation detections (the session-forgery case needed one, since a forged session produces no distinguishing event on its own).
8. **API directory disclosure** — `/api/employees` had no role restriction; classified as information disclosure rather than IDOR, and reasoned about how it silently enables ID enumeration for the read-path IDOR. Fixed and detected.

### Brute Force Chain

[Brute Force Lab](./docs/5-Brute%20Force.md)

9. **Stages 1-2: single source, then rotating sources, against one account** — found the app trusted a client-spoofable `X-Forwarded-For` header; fixed with a dual IP+username-keyed lockout.
10. **Stages 3-4: credential spraying, then distributed spraying** — found the app-level fix "worked" for the wrong reason (raw volume, not real spray detection) and was fully bypassable with rotating spoofed IPs; fixed with Nginx-level rate limiting keyed on the true (unspoofable) socket IP.
11. **CIM normalization** — mapped the app's security log to Splunk's Authentication data model, so one spray-detection query now fires correctly against both the app and real Windows Event 4625 data.
12. **Genuinely distributed spraying** — simulated a slow, many-source spray that defeats every per-source counter; caught only with a global, source-independent query. Explicitly documented as detection without prevention — no single actionable IP exists to block.

### Path Traversal

[Path Traversal Lab](./docs/6-Path%20Traversal.md)

13. **WAF bypass via absolute path** — ModSecurity reliably blocked relative traversal (`../` and encoded variants), but an absolute file path bypassed it entirely, exfiltrating the app's full source code and database (including plaintext passwords) — proving SQLi being blocked never protected that same data. Fixed with a resolved-path containment check.

---

## Tools used

Nginx, ModSecurity 3.x, OWASP Core Rule Set, Flask, PostgreSQL, Splunk Enterprise, Splunk Universal Forwarder, WSL2, Python (`requests`), Kali Linux.

---

## Disclaimer

Meridian Corp is a fictional company built entirely for this lab. All data (names, emails, "internal reference" numbers) is synthetic. The application is intentionally vulnerable and must never be exposed outside an isolated lab network.