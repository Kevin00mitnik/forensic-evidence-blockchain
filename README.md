# Forensic Evidence Ledger

A standalone, educational Python web app inspired by the academic project **“Security Enhancement of Forensic Evidence Using Block Chain.”** It fingerprints evidence files with SHA-256, stores local copies, and records custody metadata in an append-only hash-linked JSON ledger.

> **Important:** This is a local learning/demo project, not a decentralized or production blockchain. It does not provide identity verification, trusted timestamps, distributed consensus, encryption, access control, or legal chain-of-custody assurance. Anyone who can change the local ledger can rewrite it and recompute its hashes. Do not use it to manage real forensic evidence.

## Requirements

- Python 3.10 or newer
- pip

## Setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000> in your browser. The server binds to localhost only. Uploads are limited to 16 MiB each.

## Use

1. **Register evidence:** select a file. The app stores it locally, calculates its SHA-256 digest, and appends a record containing its filename, digest, UTC timestamp, and hash-chain metadata.
2. **Verify a file:** select a ledger record and upload the file to compare. The app hashes the upload in memory and reports whether it matches the registered digest.
3. **Verify the ledger:** the app recomputes each record hash and checks the link to the previous record.

Runtime files are stored under `data/` by default (`data/ledger.json` and `data/uploads/`) and are excluded from Git. Set `EVIDENCE_DATA_DIR` to use a different local directory. Set `EVIDENCE_SESSION_SECRET` only if you need a stable Flask session key across restarts; otherwise a temporary random key is generated on launch.

## Ledger format and integrity

Each record has a sequential index, random record ID, sanitized original filename, evidence SHA-256, UTC timestamp, previous record hash, and its own SHA-256 record hash. The record hash is calculated from canonical JSON for the other record fields. The first record links to an all-zero genesis hash. Ledger writes use a temporary file and an atomic replacement to avoid partially written records.

The hash chain makes accidental or limited edits detectable when checked against the later records. It is not independently protected: an attacker who can edit the ledger can recompute the chain. Evidence files and the ledger stay on the machine running the app.

## Tests

```powershell
python -m unittest discover -s tests -v
```
