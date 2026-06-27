import random
import os
import sqlite3
from datetime import date, timedelta

def load_patient_name_list(filepath):
    with open(filepath, "r") as f:
        names = [line.strip() for line in f if line.strip()]
    if len(names) < 2:
        raise ValueError("PatientNameList.txt must contain at least 2 names.")
    return names

def generate_mrn():
    return str(random.randint(100000, 999999))

def generate_ssn():
    # 900-999 area range is never assigned by the SSA — safe for synthetic use
    area   = random.randint(900, 999)
    group  = random.randint(10, 99)
    serial = random.randint(1000, 9999)
    return f"{area}-{group}-{serial}"

def generate_dob():
    start = date(1940, 1, 1)
    end   = date(2005, 12, 31)
    random_days = random.randint(0, (end - start).days)
    return (start + timedelta(days=random_days)).strftime("%Y-%m-%d")

def init_pii_db(filepath):
    conn = sqlite3.connect(filepath)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            patient_id INTEGER PRIMARY KEY,
            mrn        TEXT UNIQUE,
            first_name TEXT,
            last_name  TEXT,
            dob        TEXT,
            ssn        TEXT UNIQUE
        )
    """)
    conn.commit()
    return conn

def get_existing_unique_values(conn):
    """Load all existing MRNs and SSNs from the database to avoid collisions."""
    mrns = set(row[0] for row in conn.execute("SELECT mrn FROM patients").fetchall())
    ssns = set(row[0] for row in conn.execute("SELECT ssn FROM patients").fetchall())
    return mrns, ssns

def get_next_patient_id(conn):
    row = conn.execute("SELECT MAX(patient_id) FROM patients").fetchone()
    return (row[0] if row[0] is not None else 0) + 1

def generate_patients(count, names, used_mrns, used_ssns, start_id):
    patients = []

    for i in range(count):
        mrn = generate_mrn()
        while mrn in used_mrns:
            mrn = generate_mrn()
        used_mrns.add(mrn)

        ssn = generate_ssn()
        while ssn in used_ssns:
            ssn = generate_ssn()
        used_ssns.add(ssn)

        patients.append({
            "patient_id": start_id + i,
            "mrn":        mrn,
            "first_name": random.choice(names),
            "last_name":  random.choice(names),
            "dob":        generate_dob(),
            "ssn":        ssn
        })

    return patients

def main():
    print("=== ClearChart Synthetic Patient Data Generator ===")
    print("NOTE: All data is entirely fictional and synthetically generated.")
    print("SSNs use the 900-999 area range, which the SSA never assigns.\n")

    script_dir        = os.path.dirname(os.path.abspath(__file__))
    name_list_path    = os.path.join(script_dir, "PatientNameList.txt")
    pii_db_path       = os.path.join(script_dir, "pii.db")

    if not os.path.exists(name_list_path):
        print(f"ERROR: PatientNameList.txt not found at {name_list_path}")
        print("Please place PatientNameList.txt in the same directory as this script.")
        return

    names = load_patient_name_list(name_list_path)
    print(f"Loaded {len(names)} names from PatientNameList.txt")

    conn = init_pii_db(pii_db_path)
    used_mrns, used_ssns = get_existing_unique_values(conn)
    start_id = get_next_patient_id(conn)

    if used_mrns:
        print(f"Existing records in pii.db: {len(used_mrns)}. New records will be appended.\n")
    else:
        print("No existing records found. Starting fresh.\n")

    while True:
        try:
            count = int(input("How many patient records would you like to generate? "))
            if count < 1:
                print("Please enter a number greater than 0.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a whole number.")

    print(f"\nGenerating {count} synthetic patient records...")
    patients = generate_patients(count, names, used_mrns, used_ssns, start_id)

    cursor = conn.cursor()
    cursor.executemany(
        "INSERT INTO patients VALUES (:patient_id, :mrn, :first_name, :last_name, :dob, :ssn)",
        patients
    )
    conn.commit()
    conn.close()

    print(f"Inserted {count} records into pii.db")
    print(f"Total records now in pii.db: {start_id + count - 1}")
    print("\nSample record:")
    for k, v in patients[0].items():
        print(f"  {k}: {v}")

if __name__ == "__main__":
    main()