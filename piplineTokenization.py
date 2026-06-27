import sqlite3
import secrets
import os

def generate_token():
    return secrets.token_hex(32)

def run_pipeline(script_dir):
    pii_db_path   = os.path.join(script_dir, "pii.db")
    vault_db_path = os.path.join(script_dir, "token_vault.db")

    if not os.path.exists(pii_db_path):
        print(f"ERROR: pii.db not found at {pii_db_path}")
        print("Run generatePatients.py first.")
        return

    if os.path.exists(vault_db_path):
        os.remove(vault_db_path)

    pii_conn = sqlite3.connect(pii_db_path)
    pii_conn.row_factory = sqlite3.Row
    patients = pii_conn.execute("SELECT * FROM patients").fetchall()
    pii_conn.close()

    # token_vault.db: stores tokens for all sensitive fields plus original plaintext values.
    # The integer patient_id is the only plaintext identifier allowed here.
    # It serves as the vault-internal primary key only. The application never sees this database.
    # Access is restricted to the authorized tokenization service only.
    vault_conn   = sqlite3.connect(vault_db_path)
    vault_cursor = vault_conn.cursor()
    vault_cursor.execute("""
        CREATE TABLE patients (
            patient_id          INTEGER PRIMARY KEY,
            mrn_token           TEXT,
            first_name_token    TEXT,
            last_name_token     TEXT,
            dob_token           TEXT,
            ssn_token           TEXT,
            mrn_original        TEXT,
            first_name_original TEXT,
            last_name_original  TEXT,
            dob_original        TEXT,
            ssn_original        TEXT
        )
    """)

    for row in patients:
        vault_cursor.execute(
            "INSERT INTO patients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row["patient_id"],
                generate_token(),
                generate_token(),
                generate_token(),
                generate_token(),
                generate_token(),
                row["mrn"],
                row["first_name"],
                row["last_name"],
                row["dob"],
                row["ssn"],
            )
        )

    vault_conn.commit()
    vault_conn.close()

    print("=== Pipeline: Tokenization Only ===")
    print(f"Records : {len(patients)}")
    print(f"Output  : {vault_db_path}")
    print()
    print("token_vault.db sample (tokens + originals, patient_id as internal key only):")
    sample = sqlite3.connect(vault_db_path)
    sample.row_factory = sqlite3.Row
    row = sample.execute("SELECT * FROM patients LIMIT 1").fetchone()
    for col in row.keys():
        print(f"  {col}: {row[col]}")
    sample.close()
    print()
    print("Done.")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    run_pipeline(script_dir)