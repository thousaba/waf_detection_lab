import psycopg2
import os
import random

DB_CONFIG = {
    "host": os.environ.get("MERIDIAN_DB_HOST", "127.0.0.1"),
    "port": os.environ.get("MERIDIAN_DB_PORT", "5433"),
    "dbname": os.environ.get("MERIDIAN_DB_NAME", "meridian"),
    "user": os.environ.get("MERIDIAN_DB_USER", "meridian_app"),
    "password": os.environ.get("MERIDIAN_DB_PASSWORD", "MeridianLab2026!"),
}

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
    cur = conn.cursor()
    cur.execute("""
    DROP TABLE IF EXISTS employee_notes;
    DROP TABLE IF EXISTS employees;
    DROP TABLE IF EXISTS customers;
    DROP TABLE IF EXISTS users;

    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    );

    CREATE TABLE employees (
        id SERIAL PRIMARY KEY,
        name TEXT,
        department TEXT,
        email TEXT,
        salary INTEGER,
        internal_ref TEXT
    );

    CREATE TABLE employee_notes (
        id SERIAL PRIMARY KEY,
        employee_id INTEGER,
        note TEXT
    );

    CREATE TABLE customers (
        id SERIAL PRIMARY KEY,
        company_name TEXT,
        contact_email TEXT,
        plan TEXT
    );
    """)
    conn.commit()


def seed(conn):
    cur = conn.cursor()

    # Login users (weak/plaintext passwords are intentional for this lab)
    cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                ("admin", "admin123", "admin"))
    cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                ("hr_manager", "hrpass2026", "hr"))
    cur.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                ("analyst", "analyst!1", "employee"))

    # Employees
    for i in range(1, 41):
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        dept = random.choice(DEPARTMENTS)
        email = f"{first.lower()}.{last.lower()}@meridiancorp.example"
        salary = random.randint(45000, 145000)
        internal_ref = f"MC-{random.randint(100000, 999999)}"  # fake internal ID, not a real SSN
        cur.execute(
            "INSERT INTO employees (name, department, email, salary, internal_ref) VALUES (%s, %s, %s, %s, %s)",
            (f"{first} {last}", dept, email, salary, internal_ref),
        )

    # A couple of seed notes
    cur.execute("INSERT INTO employee_notes (employee_id, note) VALUES (%s, %s)",
                (1, "Onboarded successfully, laptop issued."))
    cur.execute("INSERT INTO employee_notes (employee_id, note) VALUES (%s, %s)",
                (2, "Requested VPN access renewal."))

    # Customers
    for name in COMPANY_NAMES:
        slug = name.lower().replace(" ", "")
        contact_email = f"contact@{slug}.example"
        plan = random.choice(PLANS)
        cur.execute(
            "INSERT INTO customers (company_name, contact_email, plan) VALUES (%s, %s, %s)",
            (name, contact_email, plan),
        )

    conn.commit()


if __name__ == "__main__":
    conn = psycopg2.connect(**DB_CONFIG)
    create_schema(conn)
    seed(conn)
    conn.close()
    print(f"Seeded {DB_CONFIG['dbname']}@{DB_CONFIG['host']}:{DB_CONFIG['port']} with fake employees, customers, and login users.")
    print("Login users: admin/admin123, hr_manager/hrpass2026, analyst/analyst!1")
