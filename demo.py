from flask import Flask, request, jsonify, send_from_directory
import sqlite3
import secrets
import os
import re
from cryptoModule import hash_value

app = Flask(__name__)

ALGORITHM = "sha256"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_token():
    return secrets.token_hex(32)

def db_path(name):
    return os.path.join(BASE_DIR, name)

def sanitize_str(value, max_length=100):
    if not isinstance(value, str):
        return None
    cleaned = value.strip()[:max_length]
    return cleaned if cleaned else None

def sanitize_ssn_last4(value):
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if len(cleaned) == 4 and cleaned.isdigit():
        return cleaned
    return None

def validate_name(value):
    """Letters, spaces, and hyphens only."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()[:50]
    if not cleaned:
        return None
    if not re.match(r"^[A-Za-z\s\-]+$", cleaned):
        return None
    return cleaned

def validate_ssn(value):
    """
    Accepts 9 digits or ###-##-#### format.
    Always returns ###-##-#### or None if invalid.
    """
    if not isinstance(value, str):
        return None
    digits = re.sub(r"[^0-9]", "", value.strip())
    if len(digits) != 9:
        return None
    return f"{digits[0:3]}-{digits[3:5]}-{digits[5:9]}"

def validate_dob(value):
    """
    Must be a valid date in YYYY-MM-DD format, between 1900 and today.
    HTML date inputs always submit in YYYY-MM-DD format regardless of browser locale.
    """
    import datetime
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", cleaned):
        return None
    try:
        parsed = datetime.date.fromisoformat(cleaned)
    except ValueError:
        return None
    if parsed.year < 1900 or parsed > datetime.date.today():
        return None
    return cleaned

def validate_mrn(value):
    """Digits only, minimum 6 characters."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()[:20]
    if not re.match(r"^\d{6,}$", cleaned):
        return None
    return cleaned

def mrn_is_unique(mrn):
    """Returns True if MRN does not already exist in pii.db."""
    conn = sqlite3.connect(db_path("pii.db"))
    row = conn.execute("SELECT 1 FROM patients WHERE mrn = ?", (mrn,)).fetchone()
    conn.close()
    return row is None

def ssn_is_unique(ssn):
    """Returns True if SSN does not already exist in pii.db."""
    conn = sqlite3.connect(db_path("pii.db"))
    row = conn.execute("SELECT 1 FROM patients WHERE ssn = ?", (ssn,)).fetchone()
    conn.close()
    return row is None

def init_databases():
    conn = sqlite3.connect(db_path("pii.db"))
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
    conn.commit(); conn.close()

    conn = sqlite3.connect(db_path("hashing.db"))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            mrn_hash        TEXT,
            first_name_hash TEXT,
            last_name_hash  TEXT,
            dob_hash        TEXT,
            ssn_hash        TEXT
        )
    """)
    conn.commit(); conn.close()

    conn = sqlite3.connect(db_path("token_vault.db"))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patients (
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
    conn.commit(); conn.close()

    conn = sqlite3.connect(db_path("layered_vault1.db"))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            last_name_token  TEXT PRIMARY KEY,
            last_name_plain  TEXT,
            last4_ssn_hash   TEXT,
            last4_ssn_token  TEXT
        )
    """)
    conn.commit(); conn.close()

    conn = sqlite3.connect(db_path("layered_link.db"))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            last4_ssn_token  TEXT PRIMARY KEY,
            last4_ssn_hash   TEXT,
            patient_id_token TEXT,
            dob_plain        TEXT,
            dob_token        TEXT
        )
    """)
    conn.commit(); conn.close()

    conn = sqlite3.connect(db_path("layered_vault2.db"))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            patient_id_token TEXT PRIMARY KEY,
            patient_id_plain INTEGER,
            first_name_plain TEXT,
            first_name_token TEXT,
            ssn_plain        TEXT,
            last4_ssn_plain  TEXT,
            mrn_plain        TEXT,
            mrn_token        TEXT
        )
    """)
    conn.commit(); conn.close()

def get_next_patient_id():
    conn = sqlite3.connect(db_path("pii.db"))
    row = conn.execute("SELECT MAX(patient_id) FROM patients").fetchone()
    conn.close()
    return (row[0] if row[0] is not None else 0) + 1

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/submit", methods=["POST"])
def submit():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request body."}), 400

    mrn        = validate_mrn(data.get("mrn", ""))
    first_name = validate_name(data.get("first_name", ""))
    last_name  = validate_name(data.get("last_name", ""))
    dob        = validate_dob(data.get("dob", ""))
    ssn        = validate_ssn(data.get("ssn", ""))

    if not mrn:
        return jsonify({"error": "MRN must be at least 6 digits, numbers only."}), 400
    if not first_name:
        return jsonify({"error": "First name must contain letters only (spaces and hyphens allowed)."}), 400
    if not last_name:
        return jsonify({"error": "Last name must contain letters only (spaces and hyphens allowed)."}), 400
    if not dob:
        return jsonify({"error": "Date of birth must be a valid date and cannot be in the future."}), 400
    if not ssn:
        return jsonify({"error": "SSN must be exactly 9 digits in format ###-##-####."}), 400
    if not mrn_is_unique(mrn):
        return jsonify({"error": f"MRN {mrn} already exists. MRNs must be unique."}), 409
    if not ssn_is_unique(ssn):
        return jsonify({"error": "SSN already exists in the system."}), 409

    patient_id = get_next_patient_id()

    # pii.db — plaintext source of truth, write-only from application perspective
    conn = sqlite3.connect(db_path("pii.db"))
    conn.execute("INSERT INTO patients VALUES (?, ?, ?, ?, ?, ?)",
        (patient_id, mrn, first_name, last_name, dob, ssn))
    conn.commit(); conn.close()

    # hashing.db — all fields hashed, no plaintext, no patient_id linkage
    conn = sqlite3.connect(db_path("hashing.db"))
    conn.execute("INSERT INTO patients VALUES (?, ?, ?, ?, ?)",
        (hash_value(mrn, ALGORITHM), hash_value(first_name, ALGORITHM),
         hash_value(last_name, ALGORITHM), hash_value(dob, ALGORITHM),
         hash_value(ssn, ALGORITHM)))
    conn.commit(); conn.close()

    # token_vault.db — CSPRNG tokens alongside originals, vault access controlled
    conn = sqlite3.connect(db_path("token_vault.db"))
    conn.execute("INSERT INTO patients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (patient_id,
         generate_token(), generate_token(), generate_token(),
         generate_token(), generate_token(),
         mrn, first_name, last_name, dob, ssn))
    conn.commit(); conn.close()

    # Layered pipeline — three isolated databases, no single breach resolves a full record
    last4_ssn        = ssn.split("-")[-1]
    last4_ssn_hash   = hash_value(last4_ssn, ALGORITHM)
    last_name_token  = generate_token()
    last4_ssn_token  = generate_token()
    patient_id_token = generate_token()
    first_name_token = generate_token()
    dob_token        = generate_token()
    mrn_token        = generate_token()

    conn = sqlite3.connect(db_path("layered_vault1.db"))
    conn.execute("INSERT INTO patients VALUES (?, ?, ?, ?)",
        (last_name_token, last_name, last4_ssn_hash, last4_ssn_token))
    conn.commit(); conn.close()

    conn = sqlite3.connect(db_path("layered_link.db"))
    conn.execute("INSERT INTO patients VALUES (?, ?, ?, ?, ?)",
        (last4_ssn_token, last4_ssn_hash, patient_id_token, dob, dob_token))
    conn.commit(); conn.close()

    conn = sqlite3.connect(db_path("layered_vault2.db"))
    conn.execute("INSERT INTO patients VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (patient_id_token, patient_id, first_name, first_name_token,
         ssn, last4_ssn, mrn, mrn_token))
    conn.commit(); conn.close()

    return jsonify({"success": True, "patient_id": patient_id})

@app.route("/query", methods=["GET"])
def query():
    pipeline  = request.args.get("pipeline", "").strip()
    ssn_last4 = sanitize_ssn_last4(request.args.get("ssn_last4", ""))
    last_name = validate_name(request.args.get("last_name", ""))

    if not pipeline:
        return jsonify({"error": "Pipeline is required."}), 400

    if not last_name or not ssn_last4:
        return jsonify({"error": "Last name and last 4 of SSN are required."}), 400

    if pipeline == "hashing":
        # Gate: hashing.db must confirm last name exists before pii.db is touched.
        # pii.db is write-only from the application layer; this gate is the only
        # read path into it, and only after hash verification passes.
        last_name_hash = hash_value(last_name, ALGORITHM)

        hconn = sqlite3.connect(db_path("hashing.db"))
        hconn.row_factory = sqlite3.Row
        hash_row = hconn.execute(
            "SELECT * FROM patients WHERE last_name_hash = ?",
            (last_name_hash,)
        ).fetchone()
        hconn.close()

        if not hash_row:
            return jsonify({"error": "No matching record found."}), 404

        pconn = sqlite3.connect(db_path("pii.db"))
        pconn.row_factory = sqlite3.Row
        pii_row = pconn.execute(
            "SELECT * FROM patients WHERE last_name = ? AND ssn LIKE ?",
            (last_name, f"%-{ssn_last4}")
        ).fetchone()
        pconn.close()

        if not pii_row:
            return jsonify({"error": "No matching record found."}), 404

        if hash_value(pii_row["ssn"], ALGORITHM) != hash_row["ssn_hash"]:
            return jsonify({"error": "Hash verification failed."}), 404

        result = {
            "patient_id": pii_row["patient_id"],
            "mrn":        pii_row["mrn"],
            "first_name": pii_row["first_name"],
            "last_name":  pii_row["last_name"],
            "dob":        pii_row["dob"],
            "ssn":        pii_row["ssn"],
        }
        return jsonify([result])

    elif pipeline == "tokenization":
        conn = sqlite3.connect(db_path("token_vault.db"))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM patients WHERE last_name_original = ? AND ssn_original LIKE ?",
            (last_name, f"%-{ssn_last4}")
        ).fetchone()
        conn.close()

        if not row:
            return jsonify({"error": "No matching record found."}), 404

        result = {
            "patient_id": row["patient_id"],
            "mrn":        row["mrn_original"],
            "first_name": row["first_name_original"],
            "last_name":  row["last_name_original"],
            "dob":        row["dob_original"],
            "ssn":        row["ssn_original"],
        }
        return jsonify([result])

    elif pipeline == "layered":
        # Step 1: Hash the last4 SSN input, query Vault 1 by last_name_plain + last4_ssn_hash
        last4_ssn_hash = hash_value(ssn_last4, ALGORITHM)

        v1 = sqlite3.connect(db_path("layered_vault1.db"))
        v1.row_factory = sqlite3.Row
        v1_row = v1.execute(
            "SELECT * FROM patients WHERE last_name_plain = ? AND last4_ssn_hash = ?",
            (last_name, last4_ssn_hash)
        ).fetchone()
        v1.close()

        if not v1_row:
            return jsonify({"error": "No matching record found in Vault 1."}), 404

        last4_ssn_token = v1_row["last4_ssn_token"]

        # Step 2: Link DB — last4_ssn_token resolves to patient_id_token
        # Verify last4_ssn_hash matches as additional confirmation
        ldb = sqlite3.connect(db_path("layered_link.db"))
        ldb.row_factory = sqlite3.Row
        ldb_row = ldb.execute(
            "SELECT * FROM patients WHERE last4_ssn_token = ? AND last4_ssn_hash = ?",
            (last4_ssn_token, last4_ssn_hash)
        ).fetchone()
        ldb.close()

        if not ldb_row:
            return jsonify({"error": "No matching record found in Link DB."}), 404

        patient_id_token = ldb_row["patient_id_token"]

        # Step 3: Vault 2 — patient_id_token resolves to full record
        v2 = sqlite3.connect(db_path("layered_vault2.db"))
        v2.row_factory = sqlite3.Row
        v2_row = v2.execute(
            "SELECT * FROM patients WHERE patient_id_token = ?",
            (patient_id_token,)
        ).fetchone()
        v2.close()

        if not v2_row:
            return jsonify({"error": "No matching record found in Vault 2."}), 404

        result = {
            "patient_id": v2_row["patient_id_plain"],
            "mrn":        v2_row["mrn_plain"],
            "first_name": v2_row["first_name_plain"],
            "last_name":  v1_row["last_name_plain"],
            "dob":        ldb_row["dob_plain"],
            "ssn":        v2_row["ssn_plain"],
        }
        return jsonify([result])

    else:
        return jsonify({"error": "Unknown pipeline."}), 400

if __name__ == "__main__":
    init_databases()
    print("\n=== ClearChart Demo Server ===")
    print("Open your browser and go to: http://127.0.0.1:5000")
    print("Press CTRL+C to stop the server.\n")
    app.run(debug=True)