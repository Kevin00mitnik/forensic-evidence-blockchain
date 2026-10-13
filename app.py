"""A small local web application for recording and verifying evidence files."""

from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from forensic_ledger import EvidenceLedger, LedgerError, sha256_file
from ethereum_ledger import EthereumEvidenceLedger

MAX_UPLOAD_BYTES = 16 * 1024 * 1024
CUSTODY_ACTIONS = ("RECEIVED", "ACCESSED", "SEALED", "TRANSFERRED")


def _save_evidence(upload: FileStorage, upload_dir: Path) -> tuple[str, Path, bool]:
    filename = secure_filename(upload.filename or "")
    if not filename:
        raise ValueError("Choose a file with a valid filename.")

    upload_dir.mkdir(parents=True, exist_ok=True)
    temporary_path: str | None = None
    digest = hashlib.sha256()
    size = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=upload_dir, prefix=".upload-", suffix=".tmp", delete=False
        ) as temporary_file:
            temporary_path = temporary_file.name
            while chunk := upload.stream.read(64 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise ValueError("The file exceeds the 16 MiB upload limit.")
                digest.update(chunk)
                temporary_file.write(chunk)
        if size == 0:
            raise ValueError("Empty evidence files are not accepted.")

        evidence_hash = digest.hexdigest()
        stored_path = upload_dir / f"{evidence_hash}.blob"
        created = not stored_path.exists()
        if created:
            os.replace(temporary_path, stored_path)
            temporary_path = None
        return evidence_hash, stored_path, created
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def create_app(
    data_dir: str | Path | None = None,
    evidence_service: Any | None = None,
    backend: str | None = None,
) -> Flask:
    app = Flask(__name__)
    default_data_dir = Path(__file__).resolve().parent / "data"
    selected_backend = (backend or os.environ.get("EVIDENCE_BACKEND", "local")).lower()
    if selected_backend not in {"local", "ethereum"}:
        raise ValueError("EVIDENCE_BACKEND must be either 'local' or 'ethereum'.")
    app.config.update(
        SECRET_KEY=os.environ.get("EVIDENCE_SESSION_SECRET") or secrets.token_hex(32),
        DATA_DIR=Path(data_dir or os.environ.get("EVIDENCE_DATA_DIR", default_data_dir)),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 64 * 1024,
        EVIDENCE_BACKEND=selected_backend,
    )
    app.config["DATA_DIR"] = Path(app.config["DATA_DIR"])
    app.config["UPLOAD_DIR"] = app.config["DATA_DIR"] / "uploads"
    if evidence_service is not None:
        ledger = evidence_service
    elif selected_backend == "ethereum":
        ledger = EthereumEvidenceLedger.from_environment()
    else:
        ledger = EvidenceLedger(app.config["DATA_DIR"] / "ledger.json")

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'"
        )
        return response

    @app.errorhandler(413)
    def request_too_large(_error):
        flash("The request exceeds the 16 MiB upload limit.", "error")
        return redirect(url_for("index"))

    @app.get("/")
    def index():
        try:
            records = ledger.read_records()
            chain_result = ledger.verify()
            ledger_error = None
        except LedgerError as exc:
            records = []
            chain_result = {"valid": False, "count": 0, "error": str(exc)}
            ledger_error = str(exc)
        return render_template(
            "index.html",
            records=list(reversed(records)),
            chain_result=chain_result,
            ledger_error=ledger_error,
            backend=app.config["EVIDENCE_BACKEND"],
            custody_actions=CUSTODY_ACTIONS,
        )

    @app.post("/evidence")
    def add_evidence():
        upload = request.files.get("evidence")
        if upload is None:
            flash("Choose an evidence file to register.", "error")
            return redirect(url_for("index"))
        try:
            evidence_hash, stored_path, created = _save_evidence(
                upload, app.config["UPLOAD_DIR"]
            )
            try:
                record = ledger.append(secure_filename(upload.filename), evidence_hash)
            except LedgerError:
                if created:
                    stored_path.unlink(missing_ok=True)
                raise
        except ValueError as exc:
            flash(str(exc), "error")
        except LedgerError as exc:
            flash(str(exc), "error")
        except OSError:
            app.logger.exception("Could not store the uploaded evidence")
            flash("The evidence file could not be stored locally.", "error")
        else:
            flash(
                f"Evidence registered as record {record['index']} "
                f"({record['evidence_sha256']}).",
                "success",
            )
        return redirect(url_for("index"))

    @app.post("/verify")
    def verify_evidence():
        upload = request.files.get("evidence")
        record_id = request.form.get("record_id", "")
        if upload is None or not secure_filename(upload.filename or ""):
            flash("Choose a file to verify.", "error")
            return redirect(url_for("index"))
        try:
            records = ledger.read_records()
            chain_result = ledger.verify()
            if not chain_result["valid"]:
                flash(
                    f"Cannot verify against an invalid ledger: {chain_result['error']}",
                    "error",
                )
                return redirect(url_for("index"))
            record = next((item for item in records if item.get("id") == record_id), None)
            if record is None:
                flash("Select an existing ledger record.", "error")
                return redirect(url_for("index"))
            uploaded_hash = sha256_file(upload.stream)
        except LedgerError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))

        if uploaded_hash == record.get("evidence_sha256"):
            flash(
                f"File matches record {record['index']} "
                f"(SHA-256 {uploaded_hash}).",
                "success",
            )
        else:
            flash(
                f"File does not match record {record.get('index')}. "
                f"Uploaded SHA-256: {uploaded_hash}.",
                "error",
            )
        return redirect(url_for("index"))

    @app.post("/verify-ledger")
    def verify_ledger():
        result = ledger.verify()
        if result["valid"]:
            label = (
                "Ethereum evidence records"
                if selected_backend == "ethereum"
                else "Ledger chain"
            )
            flash(f"{label} verified ({result['count']} records).", "success")
        else:
            label = (
                "Ethereum verification"
                if selected_backend == "ethereum"
                else "Ledger chain"
            )
            flash(f"{label} failed: {result['error']}", "error")
        return redirect(url_for("index"))

    @app.post("/custody")
    def record_custody():
        if selected_backend != "ethereum":
            flash("Custody history transactions are available in Ethereum mode.", "error")
            return redirect(url_for("index"))
        record_id = request.form.get("record_id", "")
        action = request.form.get("action", "")
        if action not in CUSTODY_ACTIONS:
            flash("Choose a valid custody action.", "error")
            return redirect(url_for("index"))
        try:
            record = ledger.record_custody(record_id, action)
        except (LedgerError, ValueError) as exc:
            flash(str(exc), "error")
        else:
            flash(
                f"Custody action {action.lower()} recorded on Ethereum "
                f"for evidence record {record['index']}.",
                "success",
            )
        return redirect(url_for("index"))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
