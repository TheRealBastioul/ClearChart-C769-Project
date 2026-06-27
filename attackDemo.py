import sqlite3
import os
import time
from cryptoModule import hash_value

ALGORITHM = "sha256"

def run_attack(script_dir):
    hashing_db_path = os.path.join(script_dir, "hashing.db")
    pii_db_path     = os.path.join(script_dir, "pii.db")

    if not os.path.exists(hashing_db_path):
        print("ERROR: hashing.db not found. Run pipelineHashing.py first.")
        return
    if not os.path.exists(pii_db_path):
        print("ERROR: pii.db not found. Run generatePatients.py first.")
        return

    hconn = sqlite3.connect(hashing_db_path)
    hconn.row_factory = sqlite3.Row
    hashed_records = hconn.execute("SELECT ssn_hash FROM patients").fetchall()
    hconn.close()

    ssn_hash_set = set(row["ssn_hash"] for row in hashed_records)

    print("=" * 60)
    print("  ClearChart — Pre-Computation Attack Demonstration")
    print("  Target   : hashing.db (Direct Hashing Pipeline)")
    print("  Method   : Full enumeration, zero prior knowledge")
    print("=" * 60)
    print(f"""
  Attacker has access to hashing.db only.
  No partial knowledge of any SSN assumed.

  Enumerating full constrained SSN space:
    Area range   : 900-999  (100 values)
    Group range  : 10-99    (90 values)
    Serial range : 0000-9999 (10,000 values)
    Max total    : 90,000,000 candidates

  Checking each candidate against all {len(ssn_hash_set)} stored hashes.
  Stopping on first match.

  Attacking...
""")

    recovered_ssn    = None
    recovered_hash   = None
    candidates_tried = 0
    start_time       = time.perf_counter()

    for area in range(900, 1000):
        for group in range(10, 100):
            for serial in range(0, 10000):
                candidate = f"{area}-{group:02d}-{serial:04d}"
                candidates_tried += 1
                candidate_hash = hash_value(candidate, ALGORITHM)

                if candidate_hash in ssn_hash_set:
                    recovered_ssn  = candidate
                    recovered_hash = candidate_hash
                    break

            if recovered_ssn:
                break

        if recovered_ssn:
            break

        elapsed_so_far = time.perf_counter() - start_time
        print(f"  Area {area} complete — {candidates_tried:,} candidates ({elapsed_so_far:.2f}s)...", end="\r")

    elapsed = time.perf_counter() - start_time
    print(" " * 65, end="\r")
    print("-" * 60)

    if recovered_ssn:
        print(f"  RESULT           : SSN RECOVERED")
        print(f"  Recovered SSN    : {recovered_ssn}")
        print(f"  Matched hash     : {recovered_hash[:32]}...")
        print(f"  Candidates tried : {candidates_tried:,}")
        print(f"  Time elapsed     : {elapsed:.6f} seconds")
        print("-" * 60)

        pconn = sqlite3.connect(pii_db_path)
        pconn.row_factory = sqlite3.Row
        pii_row = pconn.execute(
            "SELECT * FROM patients WHERE ssn = ?", (recovered_ssn,)
        ).fetchone()
        pconn.close()

        if pii_row:
            print(f"""
  Full patient record now accessible to attacker:
    Patient ID : {pii_row['patient_id']}
    Name       : {pii_row['first_name']} {pii_row['last_name']}
    DOB        : {pii_row['dob']}
    SSN        : {recovered_ssn}
    MRN        : {pii_row['mrn']}
""")
        else:
            print(f"\n  SSN recovered from hashing.db. Hash match confirmed.")
            print(f"  Record not found in pii.db — may have been added via pipeline scripts.\n")
    else:
        print(f"  RESULT: No match found after {candidates_tried:,} candidates.")
        print(f"  Time elapsed: {elapsed:.6f} seconds\n")

    print("=" * 60)
    print("  KEY FINDING")
    print("=" * 60)
    print(f"""
  Full SSN recovered in {elapsed:.6f} seconds with zero prior
  knowledge using only the hash stored in hashing.db.

  The attacker tried {candidates_tried:,} candidates before finding
  a match. All remaining records in hashing.db are equally
  vulnerable to the same attack.

  This attack requires NO access to:
    - pii.db (plaintext source of truth)
    - token_vault.db
    - Any layered pipeline database

  This attack is NOT possible against the layered pipeline.
  The application database stores only SHA-256 hashed CSPRNG
  UUID tokens. UUID tokens have no structural relationship to
  any patient identifier — there is no enumerable search space
  and no partial knowledge that constrains the attack surface.
""")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    run_attack(script_dir)