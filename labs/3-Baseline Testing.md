# Finding the WAF's Blind Spots: Baseline Testing Against a Real Target

## Recap

The [previous phase](./2-Building%20A%20Realistic%20Target.md) replaced a blank Nginx welcome page with Meridian Corp — a small internal HR panel with real (fake) data and four deliberately built vulnerabilities: SQL injection, stored XSS, IDOR, and weak authentication. With a real target in place, this phase asks the obvious next question: what does the WAF actually catch, and what does it miss?

## Step 1: A Baseline Coverage Test

Rather than guessing, a small Python script [waf_coverage_baseline.py](../waf_coverage_baseline.py) logs in as a real user and fires each vulnerability class at its real endpoint, checking not just the HTTP status code but whether the underlying attack actually succeeded — e.g. did the SQLi payload return real employee rows, did the XSS payload get stored and re-rendered unescaped, did an unauthorized user actually see another employee's salary.

The first run produced a flat result: every single attack succeeded, and nothing was blocked.

## Finding #1: The WAF Was Never Actually Blocking

The cause turned out to be a one-line configuration setting: `modsecurity.conf` had `SecRuleEngine DetectionOnly`. In this mode ModSecurity evaluates every rule, calculates anomaly scores, and writes full audit log entries — but never actually returns a 403. It behaves exactly like a working WAF in every way except the one that matters: it doesn't block anything.

This is a realistic and common misconfiguration — DetectionOnly is often the default or the setting used during initial rollout to observe rule behavior before enabling blocking, and it's easy to leave it that way indefinitely. Nothing about the logs or the setup looks broken; the WAF appears to be doing its job right up until a baseline test proves it isn't.

**Fix**: `SecRuleEngine On`.

## Step 2: Re-running the Baseline

With blocking enabled, the same test produced a very different result:

| Attack class | Blocked | Notes |
|---|---|---|
| SQL Injection (4 payloads) | 4/4 | CRS libinjection + pattern rules caught every variant |
| Stored XSS (3 payloads) | 3/3 | Caught before the payload ever reached the notes table |
| IDOR (4 employee IDs) | 0/4 | Every request succeeded — WAF has no concept of "should this user see this record" |
| Brute force (10 login attempts) | 0/10 | No rate limiting configured — all 10 attempts reached the app |

This is the real finding of the phase, and it's a genuinely useful one for detection engineering: **signature-based WAF rules are strong against payload-shaped attacks (SQLi, XSS) and structurally blind to logic-shaped attacks (IDOR, brute force).** A request for `/employees/15` looks identical whether it comes from an authorized HR manager or an attacker who simply incremented an ID in the URL — there's no payload to pattern-match against. Detecting this class of abuse requires application-level context (who is asking, what did they normally access, how fast are they iterating), not request inspection.

## Finding #2: The Same Blind Spot Exists in Logging

The gap isn't only in blocking — it's in visibility too. ModSecurity's audit log is configured with `SecAuditEngine RelevantOnly` and `SecAuditLogRelevantStatus "^(?:5|4(?!04))"`, meaning it only records requests that return a 4xx (excluding 404) or 5xx status. Since IDOR and brute-force requests both return a normal `200 OK`, **they never appear in the WAF's audit log at all** — not as blocked, not as suspicious, not as anything. As far as the WAF's own logging is concerned, those ten failed login attempts and four out-of-scope employee lookups simply didn't happen.

## Fix: Application-Level Security Logging

Since the WAF can't see (or block) logic-layer abuse, the visibility has to come from the application itself — which is also how this tends to be handled in real systems: auth events and access-control decisions are logged where the context to evaluate them actually exists.

Two lightweight additions to the Flask app:

- Every login attempt (`/login`) now logs a structured `login_success` or `login_failure` event with the attempted username, source IP, and user agent.
- Every employee record view (`/employees/<id>`) now logs an `employee_record_access` event with the viewing user, their role, and the target employee ID — the data needed to later ask "is this user viewing records outside their normal pattern."

```
event=login_failure user="admin" src_ip=10.248.52.192 user_agent="python-requests/2.34.2"
event=employee_record_access viewer_user="admin" viewer_role="admin" target_employee_id=15 src_ip=10.248.52.192
```

This log is forwarded into Splunk the same way the ModSecurity audit log is — a new Universal Forwarder `monitor` stanza pointed at `meridian_security.log`, feeding a new `web_app_security` index (created the same way `web_modsec` was created earlier in the lab, having already learned the hard way what happens when a forwarded index doesn't exist on the indexer side).

## Takeaways

- "The WAF is configured" and "the WAF is blocking" are two different claims — verify the second one directly rather than assuming it from the presence of logs or a running process.
- A baseline test against a real, statefully vulnerable target is worth far more than testing against a blank page — it surfaces both false negatives (things that should be blocked and aren't) and, just as importantly, categories of risk the WAF was never going to be able to see in the first place.
- Signature-based perimeter defenses and logic/access-control flaws live in different layers, and need different telemetry sources. A complete detection strategy has to combine WAF-level and application-level logging rather than relying on one.
- Next step: turn the now-available `web_app_security` data into real Splunk detections — repeated login failures from one source (brute force), and a single user viewing an unusual number of distinct employee records in a short window (IDOR/enumeration behavior).