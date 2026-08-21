# WAF Detection Lab

A home lab project that deploys a real Web Application Firewall (ModSecurity + OWASP CRS) in front of a deliberately vulnerable internal web application ("Meridian Corp"), generates realistic attack and user traffic against it, and forwards everything into Splunk for detection engineering work — coverage testing, correlation searches, alerting, and (eventually) automated response.

The goal isn't just "stand up a WAF" — it's to work through the full lifecycle a real detection engineer deals with: deploy → verify it's actually protecting anything → find what it misses → build detection and logging to cover the gaps → alert on it.

## Why this exists

This project is part of a broader home detection lab focused on blue-team / detection engineering skills (Splunk, MITRE ATT&CK, Active Directory security, network security monitoring). Most WAF write-ups stop at "I installed ModSecurity and it blocked an SQLi payload." This one goes further: a proper coverage baseline against a real target uncovered that the WAF wasn't blocking *anything* (misconfigured in detection-only mode), and that even once fixed, entire vulnerability classes (IDOR, brute force) pass straight through because they're invisible to signature-based rules — which is a far more realistic and useful thing to have found and fixed.

## Architecture

```
        Kali (attacker + normal-traffic simulation)
                    │
                    ▼
   Nginx + ModSecurity + OWASP CRS   (WSL2, Ubuntu)
                    │  proxy_pass
                    ▼
   Meridian Corp — Flask + SQLite app (WSL2)
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
- **Target application**: Meridian Corp — a single-file Flask + SQLite app simulating an internal HR/SaaS panel (employee records, customer accounts, login). Seeded with synthetic data only. Contains four intentional vulnerabilities (SQLi, stored XSS, IDOR, weak auth) so attack traffic has real sinks to hit instead of an empty page.
- **Log pipeline**: Splunk Universal Forwarder (WSL2) → Splunk Enterprise (native Windows host) over the standard S2S port (9997). Two indexes: `web_modsec` (WAF audit log) and `web_app_security` (app-level auth/access events the WAF can't see).
- **Traffic generation**: a Python script simulating a mix of normal browsing traffic and periodic attacker bursts (SQLi, XSS, LFI, RCE, SSRF) against the target, and a separate session-aware coverage script that logs in and tests each vulnerability class directly.

## What's been done so far

1. **WAF + Splunk pipeline setup** — deployed ModSecurity/CRS, connected the WSL2 forwarder to the Windows-side Splunk indexer, and debugged a stuck output pipeline (a stale, unrelated monitor input pointed at a non-existent index was silently blocking the entire shared TCP output queue — including the healthy WAF logs riding behind it). Also fixed ModSecurity's multi-part audit log format with a custom `LINE_BREAKER` so each transaction indexes as one Splunk event instead of five or six fragments.
   → [`01-waf-setup-and-troubleshooting.md`](./docs/1-Building%20WAF.md)

2. **Built a realistic target** — replaced the default Nginx welcome page with Meridian Corp, a small Flask/SQLite app with real (synthetic) employee and customer data and four deliberately built vulnerabilities, so attack traffic has something real to succeed or fail against.
   → [`02-meridian-corp-architecture.md`](./docs/2-Building%20A%20Realistic%20Target.md)

3. **Baseline coverage testing** — wrote a session-aware Python script that logs in and fires attacks at real endpoints, checking whether they actually succeeded rather than just reading the HTTP status. Found ModSecurity was running in `DetectionOnly` mode (logging everything, blocking nothing); after fixing that, SQLi and XSS were fully blocked but IDOR and brute force passed through completely untouched, and weren't even visible in the WAF's own audit log. Added structured application-level security logging (login attempts, record-access events) to close that visibility gap.
   → [`03-waf-blindspots-and-app-logging.md`](./docs/3-Baseline%20Testing.md)


## Tools used

Nginx, ModSecurity 3.x, OWASP Core Rule Set, Flask, SQLite, Splunk Enterprise, Splunk Universal Forwarder, WSL2, Python (`requests`), Kali Linux.

## Disclaimer

Meridian Corp is a fictional company built entirely for this lab. All data (names, emails, "internal reference" numbers) is synthetic. The application is intentionally vulnerable and must never be exposed outside an isolated lab network.