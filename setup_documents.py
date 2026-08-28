import os

BASE_DIR = os.path.dirname(__file__)
DOCS_DIR = os.path.join(BASE_DIR, "documents")

os.makedirs(DOCS_DIR, exist_ok=True)

# The "normal", intended-to-be-accessible document
with open(os.path.join(DOCS_DIR, "contract.txt"), "w") as f:
    f.write(
        "MERIDIAN CORP - EMPLOYMENT CONTRACT (sample)\n"
        "==============================================\n"
        "This is a placeholder contract document used for lab testing.\n"
        "No real terms, no real employee.\n"
    )

with open(os.path.join(DOCS_DIR, "handbook.pdf.txt"), "w") as f:
    f.write("Employee Handbook (placeholder) - lab document.\n")

# A fake "sensitive" file living OUTSIDE the documents directory,
# at the application's own base directory - a realistic traversal
# target (analogous to a real app's .env or config file sitting
# next to the app code).
with open(os.path.join(BASE_DIR, ".env"), "w") as f:
    f.write(
        "# FAKE lab secrets - not real credentials\n"
        "DB_PASSWORD=fake_sup3r_secret_db_pass\n"
        "API_KEY=fake_sk_live_1234567890abcdef\n"
        "ADMIN_BACKUP_PASSWORD=fake_backup_admin_pw!\n"
    )

print(f"Documents ready in: {DOCS_DIR}")
print(f"Fake secret file planted at: {os.path.join(BASE_DIR, '.env')}")
print("Test the normal path: /employees/1/document?file=contract.txt")
