# ClearChart - PII Protection Architecture

> **WGU C769 IT Capstone Project** · Python · Flask · SQLite

A proof of concept comparing three PII protection approaches applied to synthetic patient data in a simulated EHR intake system.

> ⚠️ All patient data is entirely synthetic. SSNs use the 900–999 area range which the SSA has never assigned.

---

## Quick Start

**Step 1 - Clone the repository and install dependencies**

```bash
git clone https://github.com/TheRealBastioul/clearchart.git
cd clearchart
pip install flask
```

**Step 2 - Generate synthetic patient data**

```bash
python generatePatients.py
```

**Step 3 - Build the pipeline databases**

```bash
python pipelineHashing.py
python piplineTokenization.py
python piplineLayered.py
```

**Step 4 - Start the web interface**

```bash
python demo.py
```

Open `http://127.0.0.1:5000` in a browser.

**Step 5 - Run the pre-computation attack demonstration (optional)**

```bash
python attackDemo.py
```

> ⚠️ `pii.db` is a demo-only seed file for generating synthetic records. In a real deployment, patient data would be written directly into the pipeline databases at intake.

---

## Architecture

### Pipeline 1 - Direct Hashing

```mermaid
flowchart TD
    INTAKE["Patient Intake
    mrn, first_name, last_name, dob, ssn"]

    HASH["cryptoModule.py
    SHA-256 hash()"]

    subgraph HDB ["hashing.db"]
        H1[mrn_hash]
        H2[first_name_hash]
        H3[last_name_hash]
        H4[dob_hash]
        H5["ssn_hash ⚠️ attack target"]
    end

    subgraph ATK ["Pre-Computation Attack"]
        A1[Enumerate 900-999 SSN area range]
        A2[Hash each candidate]
        A3[Match against ssn_hash]
        A4[SSN recovered in under 1 second]
        A1 --> A2 --> A3 --> A4
    end

    INTAKE --> HASH --> HDB
    HDB -.->|no plaintext access needed| ATK
```

---

### Pipeline 2 - Tokenization

```mermaid
flowchart TD
    INTAKE["Patient Intake
    mrn, first_name, last_name, dob, ssn"]

    TOKEN["secrets.token_hex()
    256-bit CSPRNG"]

    subgraph VAULT ["token_vault.db"]
        subgraph TOKENS ["Tokens"]
            T1[mrn_token]
            T2[first_name_token]
            T3[last_name_token]
            T4[dob_token]
            T5[ssn_token]
        end
        subgraph ORIG ["Originals"]
            O1[mrn_original]
            O2[first_name_original]
            O3[last_name_original]
            O4[dob_original]
            O5[ssn_original]
        end
    end

    WEAK["⚠️ Single-vault weakness
    One breach exposes tokens and originals together"]

    INTAKE --> TOKEN --> VAULT
    VAULT -.-> WEAK
```

---

### Pipeline 3 - Layered Tokenization-Plus-Hashing

#### Data Creation

```mermaid
flowchart TD
    INTAKE["Patient Intake
    mrn, first_name, last_name, dob, ssn"]

    subgraph V1 ["layered_vault1.db - Query Entry Point"]
        V1B["last_name_plain"]
        V1C["last4_ssn_hash"]
        V1D["last4_ssn_token"]
    end

    subgraph LDB ["layered_link.db - Bridge Layer"]
        LA["last4_ssn_token PK"]
        LB["last4_ssn_hash"]
        LC["patient_id_token"]
        LD["dob_plain"]
    end

    subgraph V2 ["layered_vault2.db - Resolution Layer"]
        V2A["patient_id_token PK"]
        V2C["first_name_plain"]
        V2D["ssn_plain"]
        V2E["mrn_plain"]
    end

    INTAKE --> V1
    INTAKE --> LDB
    INTAKE --> V2
    V1D -->|token bridge| LA
    LC -->|token bridge| V2A
```

#### Query Flow

```mermaid
flowchart TD
    USER["User input: last name + last 4 SSN"]

    V1Q["Query layered_vault1.db
    WHERE last_name_plain = input
    AND last4_ssn_hash = SHA256 of input"]

    V1R["Retrieve last4_ssn_token"]

    LDBQ["Query layered_link.db
    WHERE last4_ssn_token = token from Vault 1"]

    LDBR["Retrieve patient_id_token + dob_plain"]

    V2Q["Query layered_vault2.db
    WHERE patient_id_token = token from Link DB"]

    ASSEMBLE["Full record assembled
    last_name: Vault 1
    dob: Link DB
    ssn + mrn + first_name: Vault 2"]

    USER --> V1Q --> V1R --> LDBQ --> LDBR --> V2Q --> ASSEMBLE
```

**Breach exposure per database:**
- Vault 1: last name + partial SSN hash only
- Link DB: DOB + opaque tokens, no name or SSN
- Vault 2: SSN + MRN + first name, dead end without Link DB token

---

## Pipeline Comparison

| Property | Hashing | Tokenization | Layered |
|---|---|---|---|
| Pre-computation attack | ❌ Vulnerable | ✅ Not feasible | ✅ Not feasible |
| Single-breach exposure | ❌ High | ❌ High | ✅ Partial record only |
| Query complexity | Simple | Simple | Three hops |
| Reversibility | ❌ One-way | ✅ Vault lookup | ✅ Token chain |

---

## Author

Vincent (Bast) Herrera · [github.com/TheRealBastioul](https://github.com/TheRealBastioul) · [dimensionbeyond.space](https://dimensionbeyond.space)

*WGU B.S. Cybersecurity and Information Assurance - C769 IT Capstone*
