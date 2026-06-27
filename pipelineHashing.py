import sqlite3
import os
from cryptoModule import hash_value

ALGORITHM = "sha256"

def run_pipeline(script_dir):
    pii_db_path     = os.path.join(script_dir, "pii.db")
    hashing_db_path = os.path.join(script_dir, "hashing.db")

    if not os.path.exists(pii_db_path):
        print(f"ERROR: pii.db not found at {pii_db_path}")
        print("Run generatePatients.py first.")
        return

    if os.path.exists(hashing_db_path):
        os.remove(hashing_db_path)

    pii_conn = sqlite3.connect(pii_db_path)
    pii_conn.row_factory = sqlite3.Row
    patients = pii_conn.execute("SELECT * FROM patients").fetchall()
    pii_conn.close()

    hash_conn   = sqlite3.connect(hashing_db_path)
    hash_cursor = hash_conn.cursor()

    # No patient_id column. Hashes are stored with no linkage to the original record.
    hash_cursor.execute("""
        CREATE TABLE patients (
            mrn_hash        TEXT,
            first_name_hash TEXT,
            last_name_hash  TEXT,
            dob_hash        TEXT,
            ssn_hash        TEXT
        )
    """)

    for row in patients:
        hash_cursor.execute(
            "INSERT INTO patients VALUES (?, ?, ?, ?, ?)",
            (
                hash_value(row["mrn"],        ALGORITHM),
                hash_value(row["first_name"], ALGORITHM),
                hash_value(row["last_name"],  ALGORITHM),
                hash_value(row["dob"],        ALGORITHM),
                hash_value(row["ssn"],        ALGORITHM),
            )
        )

    hash_conn.commit()
    hash_conn.close()

    print("=== Pipeline: Direct Hashing ===")
    print(f"Algorithm : {ALGORITHM}")
    print(f"Records   : {len(patients)}")
    print(f"Output    : {hashing_db_path}")
    print()
    print("Sample (first record):")
    sample = sqlite3.connect(hashing_db_path)
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