import sqlite3
import os
import random

DB_PATH = os.path.join(os.path.dirname(__file__), "meridian.db")

FIRST_NAMES = ["Alex", "Sam", "Jordan", "Taylor", "Morgan", "Casey", "Riley",
               "Jamie", "Cameron", "Drew", "Avery", "Reese", "Quinn", "Skyler"]
LAST_NAMES = ["Turner", "Bailey", "Reed", "Foster", "Coleman", "Grant", "Hayes",
              "Simmons", "Wallace", "Owens", "Fox", "Stone", "Ward", "Price"]
DEPARTMENTS = ["Engineering", "Sales", "HR", "Finance", "IT", "Support", "Marketing"]
COMPANY_NAMES = ["Northwind Retail", "BlueRiver Logistics", "Cascade Analytics",
                  "Ironclad Manufacturing", "Solstice Media", "Harbor Point Legal",
                  "Vantage Health Group", "Pioneer Freight", "Lumen Software",
                  "Crestwood Financial"]
PLANS = ["Starter", "Professional", "Enterprise"]


def create_schema(conn):
    conn.executescript("""
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS employees;
    DROP TABLE IF EXISTS employee_notes;
    DROP TABLE IF EXISTS customers;

    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    );

    CREATE TABLE employees (
        id INTEGER PRIMARY KEY,
        name TEXT,
        department TEXT,
        email TEXT,
        salary INTEGER,
        internal_ref TEXT
    );

    CREATE TABLE employee_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id INTEGER,
        note TEXT
    );

    CREATE TABLE customers (
        id INTEGER PRIMARY KEY,
        company_name TEXT,
        contact_email TEXT,
        plan TEXT
    );
    """)


def seed(conn):
    # Login users (weak/plaintext passwords are intentional for this lab)
    conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                 ("admin", "admin123", "admin"))
    conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                 ("hr_manager", "hrpass2026", "hr"))
    conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                 ("analyst", "analyst!1", "employee"))

    # Employees
    for i in range(1, 41):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        dept = random.choice(DEPARTMENTS)
        email = f"{first.lower()}.{last.lower()}@meridiancorp.example"
        salary = random.randint(45000, 145000)
        internal_ref = f"MC-{random.randint(100000, 999999)}"  # fake internal ID, not a real SSN
        conn.execute(
            "INSERT INTO employees (name, department, email, salary, internal_ref) VALUES (?, ?, ?, ?, ?)",
            (f"{first} {last}", dept, email, salary, internal_ref),
        )

    # A couple of seed notes
    conn.execute("INSERT INTO employee_notes (employee_id, note) VALUES (?, ?)",
                 (1, "Onboarded successfully, laptop issued."))
    conn.execute("INSERT INTO employee_notes (employee_id, note) VALUES (?, ?)",
                 (2, "Requested VPN access renewal."))

    # Customers
    for name in COMPANY_NAMES:
        slug = name.lower().replace(" ", "")
        contact_email = f"contact@{slug}.example"
        plan = random.choice(PLANS)
        conn.execute(
            "INSERT INTO customers (company_name, contact_email, plan) VALUES (?, ?, ?)",
            (name, contact_email, plan),
        )

    conn.commit()


if __name__ == "__main__":
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    create_schema(conn)
    seed(conn)
    conn.close()
    print(f"Seeded {DB_PATH} with fake employees, customers, and login users.")
    print("Login users: admin/admin123, hr_manager/hrpass2026, analyst/analyst!1")
