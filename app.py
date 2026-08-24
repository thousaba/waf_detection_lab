import sqlite3
import os
import time
import logging
from flask import Flask, request, g, session, redirect, url_for, render_template_string, jsonify

DB_PATH = os.path.join(os.path.dirname(__file__), "meridian.db")
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
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()



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

        db = get_db()
        # Intentionally simple/weak auth check for lab realism (brute force telemetry)
        row = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
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


@app.route("/")
def dashboard():
    if not require_login():
        return redirect(url_for("login"))
    db = get_db()
    emp_count = db.execute("SELECT COUNT(*) c FROM employees").fetchone()["c"]
    cust_count = db.execute("SELECT COUNT(*) c FROM customers").fetchone()["c"]
    content = f"""
    <div class="card">
      <h2>Welcome, {session.get('user')}</h2>
      <p>Employees: {emp_count} &nbsp;|&nbsp; Customers: {cust_count}</p>
    </div>
    """
    return render(content)



@app.route("/employees")
def employees_list():
    if not require_login():
        return redirect(url_for("login"))
    db = get_db()
    rows = db.execute("SELECT id, name, department, email FROM employees").fetchall()
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
    if not require_login():
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    db = get_db()
    query = f"SELECT id, name, department, email FROM employees WHERE name LIKE '%{q}%'"
    try:
        rows = db.execute(query).fetchall()
        error = None
    except sqlite3.Error as e:
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


@app.route("/employees/<emp_id>")
def employee_detail(emp_id):
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

    db = get_db()
    row = db.execute("SELECT * FROM employees WHERE id = ?", (emp_id,)).fetchone()
    auth_logger.info(
        f'event=employee_record_access viewer_user="{session.get("user")}" '
        f'viewer_role="{session.get("role")}" target_employee_id={emp_id} '
        f'src_ip={client_ip()}'
    )
    if not row:
        return render("<div class='card'><p>Employee not found.</p></div>"), 404
    notes = db.execute(
        "SELECT note FROM employee_notes WHERE employee_id = ?", (emp_id,)
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

    note = request.form.get("note", "")
    db = get_db()
    db.execute(
        "INSERT INTO employee_notes (employee_id, note) VALUES (?, ?)",
        (emp_id, note),
    )
    db.commit()
    return redirect(url_for("employee_detail", emp_id=emp_id))


@app.route("/customers")
def customers_list():
    if not require_login():
        return redirect(url_for("login"))
    db = get_db()
    rows = db.execute("SELECT id, company_name, contact_email, plan FROM customers").fetchall()
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


@app.route("/api/employees")
def api_employees():
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401

    allowed_roles = {"admin", "hr"}
    if session.get("role") not in allowed_roles:
        auth_logger.info(
            f'event=access_denied reason="api_directory_scrape_attempt" viewer_user="{session.get("user")}" '
            f'viewer_role="{session.get("role")}" src_ip={client_ip()}'
        )
        return jsonify({"error": "forbidden"}), 403

    db = get_db()
    rows = db.execute("SELECT id, name, department FROM employees").fetchall()
    auth_logger.info(
        f'event=api_directory_access viewer_user="{session.get("user")}" '
        f'viewer_role="{session.get("role")}" record_count={len(rows)} '
        f'src_ip={client_ip()}'
    )
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("Database not found. Run seed_data.py first: python3 seed_data.py")
    app.run(host="0.0.0.0", port=5000, debug=False)
