import sys
import csv
import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8888"
if not TARGET.startswith("http"):
    TARGET = "http://" + TARGET

RESULTS_FILE = "waf_coverage_baseline.csv"

session = requests.Session()


def login(username="admin", password="admin123"):
    r = session.post(f"{TARGET}/login", data={"username": username, "password": password})
    ok = "Dashboard" in r.text or r.url.endswith("/") or "Welcome" in r.text
    print(f"[login] {username} -> status={r.status_code} logged_in={ok}")
    return ok


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT id,username,password,role FROM users--",
    "admin'--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

IDOR_TARGET_IDS = [1, 2, 15, 40]  


def test_sqli():
    print("\n=== SQL Injection: /employees/search ===")
    for payload in SQLI_PAYLOADS:
        r = session.get(f"{TARGET}/employees/search", params={"q": payload})
        blocked = r.status_code == 403
        leaked = (not blocked) and r.status_code == 200 and "meridiancorp.example" in r.text
        row_count = r.text.count("meridiancorp.example") if leaked else 0
        print(f"  payload={payload!r:45} status={r.status_code} blocked={blocked} leaked_rows~{row_count}")
        log_result("SQLi", payload, r.status_code, blocked, leaked)


def test_xss():
    print("\n=== Stored XSS: /employees/<id>/notes ===")
    for payload in XSS_PAYLOADS:
        r = session.post(f"{TARGET}/employees/1/notes", data={"note": payload})
        blocked = r.status_code == 403
        stored_raw = False
        if not blocked:
            detail = session.get(f"{TARGET}/employees/1")
            stored_raw = payload in detail.text
        print(f"  payload={payload!r:35} status={r.status_code} blocked={blocked} stored_unescaped={stored_raw}")
        log_result("StoredXSS", payload, r.status_code, blocked, stored_raw)


def test_idor():
    print("\n=== IDOR: /employees/<id> (as low-priv user) ===")
    for emp_id in IDOR_TARGET_IDS:
        r = session.get(f"{TARGET}/employees/{emp_id}")
        blocked = r.status_code == 403
        accessed = (not blocked) and r.status_code == 200 and "Salary" in r.text
        print(f"  employee_id={emp_id:<5} status={r.status_code} blocked={blocked} accessed_record={accessed}")
        log_result("IDOR", f"employee_id={emp_id}", r.status_code, blocked, accessed)


def test_bruteforce():
    print("\n=== Brute force: /login (10 attempts) ===")
    fresh = requests.Session()
    for i in range(10):
        r = fresh.post(f"{TARGET}/login", data={"username": "admin", "password": f"guess{i}"})
        blocked = r.status_code == 403
        print(f"  attempt={i+1:<3} status={r.status_code} blocked={blocked}")
        log_result("BruteForce", f"attempt_{i+1}", r.status_code, blocked, False)


results = []


def log_result(category, payload, status, blocked, succeeded):
    results.append({
        "category": category,
        "payload": payload,
        "http_status": status,
        "waf_blocked": blocked,
        "attack_succeeded": succeeded,
    })


def write_csv():
    with open(RESULTS_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["category", "payload", "http_status", "waf_blocked", "attack_succeeded"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\nResults written to {RESULTS_FILE}")


if __name__ == "__main__":
    if not login():
        print("Login failed — check credentials / app is running / WAF isn't blocking the login POST itself.")
        sys.exit(1)

    test_sqli()
    test_xss()
    test_idor()
    test_bruteforce()
    write_csv()

    print("\n=== Summary: attacks the WAF did NOT block AND that actually succeeded ===")
    gaps = [r for r in results if not r["waf_blocked"] and r["attack_succeeded"]]
    if gaps:
        for g in gaps:
            print(f"  [GAP] {g['category']}: {g['payload']}")
    else:
        print("  None — WAF blocked everything that would have succeeded.")