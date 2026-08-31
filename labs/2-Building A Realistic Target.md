# Building a Realistic Target: The Meridian Corp Lab Scenario

## Why a Fake Company Instead of a Blank Nginx Page?

The [first phase of this lab](./1-Building%20WAF.md.md) got ModSecurity + OWASP CRS running in front of a default Nginx welcome page, with logs flowing into Splunk. That was enough to prove the pipeline worked end-to-end, but it had an obvious limitation: attacking an empty landing page produces synthetic-feeling telemetry. A SQL injection attempt against a page with no database behind it blocks (or doesn't) at the WAF layer, but nothing downstream is actually at risk — there's no data to steal, no session to hijack, no privilege to escalate.

For the lab to produce detection engineering work that resembles a real environment, the target needed to be a real application with real (fake) data, real authentication, and a handful of genuine vulnerabilities for attacks to actually exploit — not just trip a regex.

## The Scenario: Meridian Corp

Meridian Corp is a fictional company with an internal HR/SaaS panel: employee records, customer accounts, and a login-gated dashboard. This framing gives the lab a consistent story to build around — internal vs. external traffic, an admin role vs. a regular employee role, realistic endpoint names (`/employees`, `/customers`, `/employees/<id>/notes`) instead of generic test paths.

**Stack**: a single-file Flask application backed by SQLite, seeded with synthetic data (fake names, `@meridiancorp.example` emails, fake internal reference numbers — no real people, no real PII). SQLite was chosen over a full database server to keep the lab lightweight, since the host machine has limited RAM already shared across VirtualBox VMs, Splunk, and WSL2.

### Source Code of Meridian Corp

[Meridian Corp Python Code](../app.py)

### Data model

- `users` — login accounts (admin, HR manager, regular employee), intentionally using plaintext password comparison rather than hashing, so brute-force attempts produce realistic failed-login telemetry
- `employees` — 40 seeded records: name, department, email, salary, and a fake "internal reference" number standing in for sensitive employee data
- `employee_notes` — free-text notes attached to an employee record
- `customers` — 10 seeded fictional client companies with contact details and subscription plan


### Data File 

[Data Model](../seed_data.py)


### Intentional vulnerabilities

Four vulnerabilities were deliberately built in, each chosen to give a specific class of attack a real sink to hit:

| Vulnerability | Location | Why it's there |
|---|---|---|
| SQL Injection | `/employees/search?q=` — raw string-formatted query | Gives SQLi payloads a genuine injectable target instead of always being blocked before reaching any application logic |
| Stored XSS | `/employees/<id>/notes` — note text rendered without escaping | Lets a payload persist and re-render, rather than only reflecting once |
| IDOR | `/employees/<id>` — no ownership/role check on the ID | Any authenticated user can view any employee's salary and internal reference number regardless of role |
| Weak authentication | `/login` — plaintext password comparison | Produces realistic repeated-failure telemetry for brute-force detection work |

This is obviously the opposite of how you'd build a production app — the point is to have known, documented weaknesses to attack and detect against, not to demonstrate secure coding.

## Wiring It Into the Existing Lab

The application runs as a plain Flask dev server on `127.0.0.1:5000`. The only change needed on the WAF side was updating the existing Nginx reverse proxy configuration (`/etc/nginx/sites-enabled/default`) to forward traffic to the Flask app instead of serving static files:

```nginx
location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

ModSecurity was already attached at the `server` block level (`modsecurity on;` / `modsecurity_rules_file`), so no changes were needed there — it now inspects traffic to a real application instead of a static page, with no extra configuration.

One environment-specific wrinkle worth noting: this lab runs inside WSL2, which has no `systemd`, so `systemctl reload nginx` fails with `Failed to connect to bus: Host is down`. The fix is using the SysV-style init script instead: `sudo service nginx reload` (or `sudo nginx -s reload` directly).

## Verification

After the reverse proxy change, `curl http://localhost:8888/login` returns the Meridian Corp login page instead of the Nginx default page, confirming requests are reaching the Flask app through the WAF. From here, attack traffic (SQL injection against the search endpoint, stored XSS via the notes form, brute-force login attempts) has a real application to hit, and ModSecurity's audit log — already flowing into Splunk from the previous phase — captures both the attack signature and the request that triggered it.

## What's Next

With a realistic target in place, the next phase of the lab covers:

- Reworking the traffic generator to simulate authenticated sessions (login, then browse) for both normal users and attackers, rather than unauthenticated requests to random paths
- Separating "internal employee" traffic from "external/attacker" traffic at the network level, to support anomaly detection based on source behavior
- Building correlation searches and alerts in Splunk (high anomaly score, repeated failures from one source, successful-looking exploitation attempts)
- Mapping detections to MITRE ATT&CK (T1190 – Exploit Public-Facing Application, T1110 – Brute Force)
- Adding an automated response step — a Splunk alert action that adds an attacking IP to ModSecurity's blocklist