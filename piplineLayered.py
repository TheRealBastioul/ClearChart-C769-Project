import sqlite3
import secrets
import os
from cryptoModule import hash_value

ALGORITHM = "sha256"

def generate_token():
    return secrets.token_hex(32)

def run_pipeline(script_dir):
    pii_db_path  = os.path.join(script_dir, "pii.db")
    vault1_path  = os.path.join(script_dir, "layered_vault1.db")
    linkdb_path  = os.path.join(script_dir, "layered_link.db")
    vault2_path  = os.path.join(script_dir, "layered_vault2.db")

    if not os.path.exists(pii_db_path):
        print(f"ERROR: pii.db not found at {pii_db_path}")
        print("Run generatePatients.py first.")
        return

    for path in [vault1_path, linkdb_path, vault2_path]:
        if os.path.exists(path):
            os.remove(path)

    pii_conn = sqlite3.connect(pii_db_path)
    pii_conn.row_factory = sqlite3.Row
    patients = pii_conn.execute("SELECT * FROM patients").fetchall()
    pii_conn.close()

    # Vault 1: query entry point
    # last_name_plain is the only plaintext identifier here.
    # last4_ssn_hash is SHA-256 of the last 4 SSN digits — deterministic so it
    # can be recomputed at query time from user input.
    # last4_ssn_token is a CSPRNG bridge key linking to the link DB.
    # An attacker who breaches Vault 1 sees last names, a crackable-but-low-value
    # hash of only 4 SSN digits, and an opaque CSPRNG token. No full SSN, no MRN,
    # no DOB, no first name.
    v1 = sqlite3.connect(vault1_path)
    v1.execute("""
        CREATE TABLE patients (
            last_name_token  TEXT PRIMARY KEY,
            last_name_plain  TEXT,
            last4_ssn_hash   TEXT,
            last4_ssn_token  TEXT
        )
    """)

    # Link DB: bridge layer
    # Keyed by last4_ssn_token from Vault 1.
    # Stores DOB here rather than Vault 1 so a Vault 1 breach only exposes
    # last name — DOB and SSN are split across separate databases.
    # An attacker who breaches only the Link DB sees DOB and tokens but no name or SSN.
    ldb = sqlite3.connect(linkdb_path)
    ldb.execute("""
        CREATE TABLE patients (
            last4_ssn_token   TEXT PRIMARY KEY,
            last4_ssn_hash    TEXT,
            patient_id_token  TEXT,
            dob_plain         TEXT,
            dob_token         TEXT
        )
    """)

    # Vault 2: resolution layer
    # Keyed by patient_id_token from the link DB.
    # Contains SSN, first name, MRN. No DOB (in Link DB), no last name (in Vault 1).
    # An attacker who breaches Vault 2 cannot query it without patient_id_token,
    # which only exists in the link DB. Vault 2 alone is a dead end.
    v2 = sqlite3.connect(vault2_path)
    v2.execute("""
        CREATE TABLE patients (
            patient_id_token  TEXT PRIMARY KEY,
            patient_id_plain  INTEGER,
            first_name_plain  TEXT,
            first_name_token  TEXT,
            ssn_plain         TEXT,
            last4_ssn_plain   TEXT,
            mrn_plain         TEXT,
            mrn_token         TEXT
        )
    """)

    for row in patients:
        last4_ssn = row["ssn"].split("-")[-1]

        last_name_token  = generate_token()
        last4_ssn_token  = generate_token()
        patient_id_token = generate_token()
        first_name_token = generate_token()
        dob_token        = generate_token()
        mrn_token        = generate_token()

        last4_ssn_hash = hash_value(last4_ssn, ALGORITHM)

        v1.execute(
            "INSERT INTO patients VALUES (?, ?, ?, ?)",
            (last_name_token, row["last_name"], last4_ssn_hash, last4_ssn_token)
        )

        ldb.execute(
            "INSERT INTO patients VALUES (?, ?, ?, ?, ?)",
            (last4_ssn_token, last4_ssn_hash, patient_id_token, row["dob"], dob_token)
        )

        v2.execute(
            "INSERT INTO patients VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                patient_id_token,
                row["patient_id"],
                row["first_name"],
                first_name_token,
                row["ssn"],
                last4_ssn,
                row["mrn"],
                mrn_token,
            )
        )

    v1.commit();  v1.close()
    ldb.commit(); ldb.close()
    v2.commit();  v2.close()

    print("=== Pipeline: Layered (3-Database Architecture) ===")
    print(f"Algorithm  : {ALGORITHM}")
    print(f"Records    : {len(patients)}")
    print(f"Vault 1    : {vault1_path}")
    print(f"Link DB    : {linkdb_path}")
    print(f"Vault 2    : {vault2_path}")
    print()

    print("Vault 1 sample:")
    s = sqlite3.connect(vault1_path); s.row_factory = sqlite3.Row
    r = s.execute("SELECT * FROM patients LIMIT 1").fetchone()
    for col in r.keys(): print(f"  {col}: {r[col]}")
    s.close(); print()

    print("Link DB sample:")
    s = sqlite3.connect(linkdb_path); s.row_factory = sqlite3.Row
    r = s.execute("SELECT * FROM patients LIMIT 1").fetchone()
    for col in r.keys(): print(f"  {col}: {r[col]}")
    s.close(); print()

    print("Vault 2 sample:")
    s = sqlite3.connect(vault2_path); s.row_factory = sqlite3.Row
    r = s.execute("SELECT * FROM patients LIMIT 1").fetchone()
    for col in r.keys(): print(f"  {col}: {r[col]}")
    s.close(); print()

    print("Done.")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    run_pipeline(script_dir)