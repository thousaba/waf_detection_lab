import sqlite3
import os
import logging
from flask import Flask, request, g, session, redirect, url_for, render_template_string, jsonify

DB_PATH = os.path.join(os.path.dirname(__file__), "meridian.db")
app = Flask(__name__)
app.secret_key = "lab-only-not-a-real-secret"
auth_logger = logging.getLogger("meridian_security")
auth_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__), "meridian_security.log"))
_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
auth_logger.addHandler(_handler)


def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr



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
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()

        row = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        if row:
            session["user"] = username
            session["role"] = row["role"]
            auth_logger.info(
                f'event=login_success user="{username}" src_ip={client_ip()} '
                f'user_agent="{request.headers.get("User-Agent", "")}"'
            )
            return redirect(url_for("dashboard"))
        auth_logger.info(
            f'event=login_failure user="{username}" src_ip={client_ip()} '
            f'user_agent="{request.headers.get("User-Agent", "")}"'
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
    """
    INTENTIONALLY VULNERABLE: raw string-formatted SQL query.
    This exists so SQLi payloads against a lab WAF have a real
    injectable sink to hit, instead of always being blocked before
    reaching any application logic.
    """
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
    """
    INTENTIONALLY VULNERABLE: no check that the logged-in user is
    allowed to view this specific employee record (IDOR).
    """
    if not require_login():
        return redirect(url_for("login"))
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
    """INTENTIONALLY VULNERABLE: note content is stored and rendered
    without escaping in employee_detail() above -> stored XSS."""
    if not require_login():
        return redirect(url_for("login"))
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
    db = get_db()
    rows = db.execute("SELECT id, name, department FROM employees").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("Database not found. Run seed_data.py first: python3 seed_data.py")
    app.run(host="0.0.0.0", port=5000, debug=False)
