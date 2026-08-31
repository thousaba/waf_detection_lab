# Building a WAF Detection Pipeline: When Everything Looks Fine but No Data Arrives


## Overview

As part of my home detection lab, I wanted to add web application attack visibility alongside my existing Windows/Sysmon and network monitoring stack. The goal: deploy a real Web Application Firewall (ModSecurity + OWASP CRS), generate attack traffic against it, and forward the resulting logs into Splunk for detection engineering work — correlation rules, dashboards, and eventually mapping detections to MITRE ATT&CK (T1190 – Exploit Public-Facing Application).

This post covers the setup and, more importantly, a troubleshooting case where a completely unrelated component silently broke the whole forwarding pipeline — a good reminder that "the connection is up" doesn't mean "the data is flowing."


## Architecture

- **WAF**: Nginx + ModSecurity 3.x with OWASP Core Rule Set 4.30.0-dev, running inside WSL2 (Ubuntu) on the same lab host as the rest of my Windows-based detection stack.
- **Log source**: `modsec_audit.log`, ModSecurity's native audit log format.
- **Forwarding**: Splunk Universal Forwarder inside WSL2, sending data over `127.0.0.1:9997` to a Splunk Enterprise instance running natively on the Windows host (WSL2's localhost forwarding makes this possible without extra network configuration).
- **Attack traffic**: generated manually with `curl`, including basic SQL injection payloads (`?id=1' OR 1=1`) to trigger CRS rules (e.g. rule 942100 — SQLi detection via libinjection).

Indexes were split by source (`web_modsec` for WAF data), consistent with how the rest of the lab separates Windows, Sysmon, and network data into their own indexes.


## The Problem: Connected, but Nothing Arrives

After configuring the forwarder and confirming ModSecurity was actively logging attacks (SQLi detections, anomaly scores, blocked requests all visible in the raw log file), no events showed up in Splunk under `index=web_modsec`.

The confusing part: every surface-level check looked healthy.

- `netstat` on the Windows host showed the receiving port (9997) `LISTENING`, with an `ESTABLISHED` connection from the forwarder.
- The forwarder's own log confirmed it had added a watch on the correct file path.
- File permissions were fine — `splunkd` ran as root inside WSL2 and could read the log without issue.
- No license violations, no obvious disk space issues.

Yet the forwarder's log kept repeating a specific warning:

```
WARN TcpOutputProc - The TCP output processor has paused the data flow ...
has been blocked for blocked_seconds=<N>
```

`blocked_seconds` kept climbing, and the connection to the indexer was being torn down and re-established roughly every 30 seconds (`reuse=0` each time) instead of staying open — a classic sign of backpressure somewhere in the pipeline, not a network-level failure.


## Root Cause

The forwarder's `inputs.conf` wasn't only monitoring the ModSecurity log — it also had a leftover stanza from an earlier Zeek experiment:

```
[monitor:///opt/zeek/logs/current/*.log]
index = zeek
sourcetype = zeek_json
```

The `zeek` index had never been created on the Windows-side indexer. Since a single Universal Forwarder uses one shared `tcpout` pipeline for all its monitored inputs by default, data destined for a non-existent index was enough to stall the *entire* output queue — including the unrelated, perfectly healthy ModSecurity log sitting right behind it in the same pipe.

This is the part worth remembering: a forwarder's TCP-level health (port open, connection established) says nothing about whether the *application-layer* S2S protocol is actually able to push data through. The indexer wasn't rejecting the connection — it was rejecting specific data, and that was enough to back up everything else queued behind it.

**Fix**: removed the stale Zeek monitor stanza (the index didn't exist and Zeek wasn't even part of this experiment), restarted the forwarder, and the `blocked_seconds` warnings disappeared immediately. ModSecurity events started flowing into `web_modsec` on the next restart cycle.

## Second Issue: Multi-Part Events

Once data was flowing, a second problem became clear. ModSecurity's audit log format writes each transaction as multiple parts, delimited by boundary markers:

```
---<id>---A--   (metadata)
---<id>---B--   (request headers)
---<id>---F--   (response headers)
---<id>---H--   (ModSecurity messages / rule matches)
---<id>---Z--   (end of transaction)
```

By default, Splunk was treating each part as a separate event, which meant a single SQL injection attempt showed up as five or six disconnected log entries — the request and the rule match that explained *why* it was blocked ended up in different events, joinable only by manually filtering on `unique_id`.

**Fix**: added a custom line-breaking rule in `props.conf` on the indexer, keyed on the transaction's opening boundary (`---<id>---A--`), so that everything between the start and end of a transaction is treated as a single Splunk event:

```
[modsecurity]
LINE_BREAKER = ([\r\n]+)---[a-zA-Z0-9]+---A--
SHOULD_LINEMERGE = false
TIME_PREFIX = ^\[
TIME_FORMAT = %d/%b/%Y:%H:%M:%S %z
MAX_TIMESTAMP_LOOKAHEAD = 30
```

This is parse-time configuration, so it only applies going forward — existing indexed events had to be cleaned and re-ingested to get consistent formatting across the dataset.

The result: one attack, one event — request, response, and every triggered CRS rule (including the calculated anomaly score) all in a single searchable record.

## Takeaways

- A green TCP connection is not proof that data is being accepted — application-layer backpressure can hide behind a technically "healthy" connection.
- Shared output pipelines mean one misconfigured input can silently starve every other input riding the same queue. Isolating inputs (or at minimum, keeping `inputs.conf` free of stale/experimental stanzas) avoids this class of bug entirely.
- Multi-part log formats need explicit line-breaking configuration, or correlation between a request and the rule that blocked it becomes needlessly manual.
- Next step: build a correlation search / alert on `TX:BLOCKING_INBOUND_ANOMALY_SCORE` and specific high-confidence rule IDs (e.g. 942100 for SQLi), and map the detection back to MITRE ATT&CK T1190.