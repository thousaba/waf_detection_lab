import os
import time
import logging
import psycopg2
import psycopg2.extras
from flask import Flask, request, g, session, redirect, url_for, render_template_string, jsonify

DB_CONFIG = {
    "host": os.environ.get("MERIDIAN_DB_HOST", "127.0.0.1"),
    "port": os.environ.get("MERIDIAN_DB_PORT", "5433"),
    "dbname": os.environ.get("MERIDIAN_DB_NAME", "meridian"),
    "user": os.environ.get("MERIDIAN_DB_USER", "meridian_app"),
    "password": os.environ.get("MERIDIAN_DB_PASSWORD", "MeridianLab2026!"),
}
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)

auth_logger = logging.getLogger("meridian_security")
auth_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__), "meridian_security.log"))
_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
auth_logger.addHandler(_handler)


MAX_FAILURES = 5
WINDOW_SECONDS = 300      # 5 minutes
LOCKOUT_SECONDS = 900     # 15 minutes
_failures = {}       # key (ip or username) -> list of failure timestamps
_locked_until = {}   # key -> unix timestamp when lockout ends


def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


def _is_locked(key):
    until = _locked_until.get(key)
    if until and time.time() < until:
        return True
    if until and time.time() >= until:
        _locked_until.pop(key, None)
        _failures.pop(key, None)
    return False


def _record_failure(key):
    now = time.time()
    attempts = _failures.setdefault(key, [])
    attempts.append(now)
    _failures[key] = [t for t in attempts if now - t <= WINDOW_SECONDS]
    if len(_failures[key]) >= MAX_FAILURES:
        _locked_until[key] = now + LOCKOUT_SECONDS
        return True
    return False


def _clear_failures(key):
    _failures.pop(key, None)
    _locked_until.pop(key, None)


def is_locked_out(ip, username):
    return _is_locked(f"ip:{ip}") or _is_locked(f"user:{username}")


def record_login_failure(ip, username):
    locked_ip = _record_failure(f"ip:{ip}")
    locked_user = _record_failure(f"user:{username}")
    return locked_ip, locked_user


def clear_login_failures(ip, username):
    _clear_failures(f"ip:{ip}")
    _clear_failures(f"user:{username}")



def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(cursor_factory=psycopg2.extras.RealDictCursor, **DB_CONFIG)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def db_exec(sql, params=None):
    cur = get_db().cursor()
    if params is None:
        cur.execute(sql)
    else:
        cur.execute(sql, params)
    return cur


# ---------------------------------------------------------------------
# Templates (inline for a single-file lab app)
# ---------------------------------------------------------------------

LAYOUT = """
<!DOCTYPE html>
<html>
<head>
  <title>Meridian Corp - Internal Panel</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f4f6f8; }
    .navbar { background: #1e3a5f; color: white; padding: 12px 20px; margin: -40px -40px 20px -40px; }
    .navbar a { color: white; margin-right: 16px; text-decoration: none; }
    table { border-collapse: collapse; width: 100%; background: white; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #eef2f5; }
    .card { background: white; padding: 20px; border-radius: 6px; margin-bottom: 20px; }
    input[type=text], input[type=password] { padding: 6px; width: 250px; }
    button { padding: 6px 14px; background: #1e3a5f; color: white; border: none; cursor: pointer; }
  </style>
</head>
<body>
  <div class="navbar">
    <b>Meridian Corp</b> &nbsp;|&nbsp;
    <a href="/">Dashboard</a>
    <a href="/employees">Employees</a>
    <a href="/customers">Customers</a>
    <a href="/logout">Logout</a>
  </div>
  {{ content|safe }}
</body>
</html>
"""


def render(content):
    return render_template_string(LAYOUT, content=content)


def require_login():
    return session.get("user") is not None


# ---------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    ip = client_ip()
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if is_locked_out(ip, username):
            auth_logger.info(
                f'event=login_blocked reason="rate_limited" user="{username}" src_ip={ip} '
                f'user_agent="{request.headers.get("User-Agent", "")}"'
            )
            error = "Too many failed attempts. Try again later."
            form = f"""
            <div class="card" style="max-width:350px;margin:60px auto;">
              <h2>Meridian Corp Login</h2>
              <p style='color:red;'>{error}</p>
            </div>
            """
            return render(form), 429

        # Intentionally simple/weak auth check for lab realism (brute force telemetry)
        row = db_exec(
            "SELECT * FROM users WHERE username = %s AND password = %s",
            (username, password),
        ).fetchone()
        if row:
            clear_login_failures(ip, username)
            session["user"] = username
            session["role"] = row["role"]
            auth_logger.info(
                f'event=login_success user="{username}" src_ip={ip} '
                f'user_agent="{request.headers.get("User-Agent", "")}"'
            )
            return redirect(url_for("dashboard"))

        locked_ip, locked_user = record_login_failure(ip, username)
        auth_logger.info(
            f'event=login_failure user="{username}" src_ip={ip} '
            f'user_agent="{request.headers.get("User-Agent", "")}"'
        )
        if locked_ip:
            auth_logger.info(
                f'event=account_locked reason="ip_threshold" src_ip={ip} '
                f'threshold={MAX_FAILURES} window_seconds={WINDOW_SECONDS} lockout_seconds={LOCKOUT_SECONDS}'
            )
        if locked_user:
            auth_logger.info(
                f'event=account_locked reason="username_threshold" user="{username}" src_ip={ip} '
                f'threshold={MAX_FAILURES} window_seconds={WINDOW_SECONDS} lockout_seconds={LOCKOUT_SECONDS}'
            )
        error = "Invalid credentials"
    form = f"""
    <div class="card" style="max-width:350px;margin:60px auto;">
      <h2>Meridian Corp Login</h2>
      {"<p style='color:red;'>" + error + "</p>" if error else ""}
      <form method="post">
        <p>Username: <input type="text" name="username"></p>
        <p>Password: <input type="password" name="password"></p>
        <button type="submit">Log in</button>
      </form>
    </div>
    """
    return render(form)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------

@app.route("/")
def dashboard():
    if not require_login():
        return redirect(url_for("login"))
    emp_count = db_exec("SELECT COUNT(*) c FROM employees").fetchone()["c"]
    cust_count = db_exec("SELECT COUNT(*) c FROM customers").fetchone()["c"]
    content = f"""
    <div class="card">
      <h2>Welcome, {session.get('user')}</h2>
      <p>Employees: {emp_count} &nbsp;|&nbsp; Customers: {cust_count}</p>
    </div>
    """
    return render(content)


# ---------------------------------------------------------------------
# Employees (list, search - SQLi target, detail - IDOR target, notes - XSS target)
# ---------------------------------------------------------------------

@app.route("/employees")
def employees_list():
    if not require_login():
        return redirect(url_for("login"))
    rows = db_exec("SELECT id, name, department, email FROM employees").fetchall()
    rows_html = "".join(
        f"<tr><td><a href='/employees/{r['id']}'>{r['id']}</a></td>"
        f"<td>{r['name']}</td><td>{r['department']}</td><td>{r['email']}</td></tr>"
        for r in rows
    )
    content = f"""
    <div class="card">
      <h2>Employees</h2>
      <form method="get" action="/employees/search">
        <input type="text" name="q" placeholder="Search by name...">
        <button type="submit">Search</button>
      </form>
    </div>
    <table>
      <tr><th>ID</th><th>Name</th><th>Department</th><th>Email</th></tr>
      {rows_html}
    </table>
    """
    return render(content)


@app.route("/employees/search")
def employees_search():
    """
    INTENTIONALLY VULNERABLE: raw string-formatted SQL query.
    This exists so SQLi payloads against a lab WAF have a real
    injectable sink to hit, instead of always being blocked before
    reaching any application logic.
    """
    if not require_login():
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    query = f"SELECT id, name, department, email FROM employees WHERE name LIKE '%{q}%'"
    try:
        rows = db_exec(query).fetchall()
        error = None
    except psycopg2.Error as e:
        rows = []
        error = str(e)
    rows_html = "".join(
        f"<tr><td>{r['id']}</td><td>{r['name']}</td><td>{r['department']}</td><td>{r['email']}</td></tr>"
        for r in rows
    )
    content = f"""
    <div class="card">
      <h2>Search results for "{q}"</h2>
      {"<p style='color:red;'>DB error: " + error + "</p>" if error else ""}
    </div>
    <table>
      <tr><th>ID</th><th>Name</th><th>Department</th><th>Email</th></tr>
      {rows_html}
    </table>
    """
    return render(content)


DOCS_DIR = os.path.join(os.path.dirname(__file__), "documents")


@app.route("/employees/<emp_id>/document")
def employee_document(emp_id):
    """
    FIXED (was path traversal): filename now has its resolved
    (realpath) location checked against DOCS_DIR's resolved root
    before being opened. This closes BOTH relative traversal
    (../../etc/passwd, which the WAF also blocks) AND the more
    dangerous bypass that was actually found: an absolute path in
    the `file` parameter, which os.path.join() happily returns
    unchanged (discarding DOCS_DIR entirely per Python's own
    documented join() semantics) and which contains no "../" for
    ModSecurity's LFI signature to match. Confirmed via this bypass
    that the app's own source code (app.py) and full database
    (meridian.db, including plaintext user passwords) were both
    directly readable this way, independent of the WAF layer.
    """
    if not require_login():
        return redirect(url_for("login"))
    filename = request.args.get("file", "contract.txt")
    docs_root = os.path.realpath(DOCS_DIR)
    requested_path = os.path.realpath(os.path.join(DOCS_DIR, filename))
    if requested_path != docs_root and not requested_path.startswith(docs_root + os.sep):
        auth_logger.info(
            f'event=access_denied reason="path_traversal_attempt" viewer_user="{session.get("user")}" '
            f'requested_file="{filename}" src_ip={client_ip()}'
        )
        return render("<div class='card'><p>403 - Invalid document path.</p></div>"), 403
    try:
        with open(requested_path, "r", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return render(f"<div class='card'><p>Could not read file: {e}</p></div>"), 404
    return render(f"<div class='card'><h3>Document: {filename}</h3><pre>{content}</pre></div>")



@app.route("/employees/<emp_id>")
def employee_detail(emp_id):
    """
    FIXED (was IDOR): only admin/hr roles may view employee detail
    records. Previously any authenticated user could view any
    employee's record (including salary and internal reference
    number) by simply changing the ID in the URL — confirmed via
    Splunk detection (repeated employee_record_access events from a
    single low-privilege user against multiple distinct IDs) and a
    manual curl-based reproduction as the "analyst" user.
    """
    if not require_login():
        return redirect(url_for("login"))

    allowed_roles = {"admin", "hr"}
    if session.get("role") not in allowed_roles:
        auth_logger.info(
            f'event=access_denied reason="idor_attempt" viewer_user="{session.get("user")}" '
            f'viewer_role="{session.get("role")}" target_employee_id={emp_id} '
            f'src_ip={client_ip()}'
        )
        return render("<div class='card'><p>403 - You do not have permission to view this record.</p></div>"), 403

    if not emp_id.isdigit():
        return render("<div class='card'><p>Employee not found.</p></div>"), 404

    row = db_exec("SELECT * FROM employees WHERE id = %s::int", (emp_id,)).fetchone()
    auth_logger.info(
        f'event=employee_record_access viewer_user="{session.get("user")}" '
        f'viewer_role="{session.get("role")}" target_employee_id={emp_id} '
        f'src_ip={client_ip()}'
    )
    if not row:
        return render("<div class='card'><p>Employee not found.</p></div>"), 404
    notes = db_exec(
        "SELECT note FROM employee_notes WHERE employee_id = %s::int", (emp_id,)
    ).fetchall()
    notes_html = "".join(f"<li>{n['note']}</li>" for n in notes)  # intentionally unescaped -> stored XSS sink
    content = f"""
    <div class="card">
      <h2>{row['name']}</h2>
      <p>Department: {row['department']}</p>
      <p>Email: {row['email']}</p>
      <p>Salary: {row['salary']}</p>
      <p>SSN-like internal ref (fake): {row['internal_ref']}</p>
    </div>
    <div class="card">
      <h3>Notes</h3>
      <ul>{notes_html}</ul>
      <form method="post" action="/employees/{emp_id}/notes">
        <input type="text" name="note" placeholder="Add a note...">
        <button type="submit">Add</button>
      </form>
    </div>
    """
    return render(content)


@app.route("/employees/<emp_id>/notes", methods=["POST"])
def add_note(emp_id):
    """
    FIXED (was write-path IDOR): previously any authenticated user
    could add a note to ANY employee's record regardless of role —
    confirmed via Burp Suite as the "analyst" (employee-role) user,
    who successfully injected a note into a record they can't even
    view themselves post-fix. This is a distinct finding from the
    read-path IDOR: combined with the stored-XSS sink this field
    renders into, a write-path bypass lets a low-privilege attacker
    target a payload at a record a HIGHER-privilege user (admin/hr)
    is likely to view — widening the blast radius of the XSS rather
    than confining it to the attacker's own record.
    """
    if not require_login():
        return redirect(url_for("login"))

    allowed_roles = {"admin", "hr"}
    if session.get("role") not in allowed_roles:
        auth_logger.info(
            f'event=access_denied reason="idor_write_attempt" viewer_user="{session.get("user")}" '
            f'viewer_role="{session.get("role")}" target_employee_id={emp_id} '
            f'src_ip={client_ip()}'
        )
        return render("<div class='card'><p>403 - You do not have permission to modify this record.</p></div>"), 403

    if not emp_id.isdigit():
        return render("<div class='card'><p>Employee not found.</p></div>"), 404

    note = request.form.get("note", "")
    db_exec(
        "INSERT INTO employee_notes (employee_id, note) VALUES (%s::int, %s)",
        (emp_id, note),
    )
    get_db().commit()
    return redirect(url_for("employee_detail", emp_id=emp_id))


# ---------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------

@app.route("/customers")
def customers_list():
    if not require_login():
        return redirect(url_for("login"))
    rows = db_exec("SELECT id, company_name, contact_email, plan FROM customers").fetchall()
    rows_html = "".join(
        f"<tr><td>{r['id']}</td><td>{r['company_name']}</td><td>{r['contact_email']}</td><td>{r['plan']}</td></tr>"
        for r in rows
    )
    content = f"""
    <div class="card"><h2>Customers</h2></div>
    <table>
      <tr><th>ID</th><th>Company</th><th>Contact</th><th>Plan</th></tr>
      {rows_html}
    </table>
    """
    return render(content)


# ---------------------------------------------------------------------
# Simple JSON API (a second, less HTML-noisy target for automated tools)
# ---------------------------------------------------------------------

@app.route("/api/employees")
def api_employees():
    """
    FIXED (was missing authorization): this endpoint returned the
    full employee directory (id, name, department) to any
    authenticated user regardless of role. While it doesn't expose
    salary/internal_ref the way /employees/<id> does, it hands an
    attacker two things a slower, noisier approach would cost them:
      1. A ready-made target list for spear phishing, pre-filtered
         by department in one response.
      2. A silent way to enumerate every valid employee ID without
         the fuzzing noise (1..N requests hitting /employees/<id>)
         that would otherwise show up as an obvious scanning pattern
         in Splunk/WAF logs.
    Restricted to the same admin/hr roles as the rest of the
    employee-data endpoints, and access is now logged so unusually
    frequent pulls of the full directory can be monitored for.
    """
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401

    allowed_roles = {"admin", "hr"}
    if session.get("role") not in allowed_roles:
        auth_logger.info(
            f'event=access_denied reason="api_directory_scrape_attempt" viewer_user="{session.get("user")}" '
            f'viewer_role="{session.get("role")}" src_ip={client_ip()}'
        )
        return jsonify({"error": "forbidden"}), 403

    rows = db_exec("SELECT id, name, department FROM employees").fetchall()
    auth_logger.info(
        f'event=api_directory_access viewer_user="{session.get("user")}" '
        f'viewer_role="{session.get("role")}" record_count={len(rows)} '
        f'src_ip={client_ip()}'
    )
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    try:
        psycopg2.connect(**DB_CONFIG).close()
    except psycopg2.OperationalError as e:
        print(f"Could not reach the database ({e}). Run seed_data.py first: python3 seed_data.py")
    app.run(host="0.0.0.0", port=5000, debug=False)
