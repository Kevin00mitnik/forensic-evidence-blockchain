"""Local, append-only hash-chain storage for educational evidence records."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO
from uuid import uuid4

GENESIS_HASH = "0" * 64


class LedgerError(Exception):
    """Raised when the local ledger cannot be read or safely updated."""


def sha256_file(file_object: BinaryIO) -> str:
    """Return the SHA-256 digest of a binary file-like object."""
    digest = hashlib.sha256()
    while chunk := file_object.read(64 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


class EvidenceLedger:
    """Persist evidence metadata in a JSON file linked by record hashes."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    def read_records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            with self.path.open("r", encoding="utf-8") as ledger_file:
                records = json.load(ledger_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise LedgerError(f"Could not read the ledger: {exc}") from exc
        if not isinstance(records, list):
            raise LedgerError("Ledger format is invalid: expected a JSON list.")
        return records

    @staticmethod
    def _record_hash(record: dict[str, Any]) -> str:
        canonical = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @classmethod
    def _check_records(cls, records: list[dict[str, Any]]) -> dict[str, Any]:
        previous_hash = GENESIS_HASH
        for expected_index, record in enumerate(records, start=1):
            if not isinstance(record, dict):
                return {
                    "valid": False,
                    "count": len(records),
                    "error": f"Record {expected_index} is not a JSON object.",
                }
            record_hash = record.get("record_hash")
            payload = {key: value for key, value in record.items() if key != "record_hash"}
            if record.get("index") != expected_index:
                error = f"Record {expected_index} has an invalid index."
            elif record.get("previous_hash") != previous_hash:
                error = f"Record {expected_index} does not link to its predecessor."
            elif not isinstance(record_hash, str) or cls._record_hash(payload) != record_hash:
                error = f"Record {expected_index} hash does not match its contents."
            else:
                previous_hash = record_hash
                continue
            return {"valid": False, "count": len(records), "error": error}
        return {"valid": True, "count": len(records), "error": None}

    def verify(self) -> dict[str, Any]:
        try:
            return self._check_records(self.read_records())
        except LedgerError as exc:
            return {"valid": False, "count": 0, "error": str(exc)}

    def append(self, filename: str, evidence_hash: str) -> dict[str, Any]:
        with self._lock:
            records = self.read_records()
            result = self._check_records(records)
            if not result["valid"]:
                raise LedgerError(
                    f"Ledger integrity check failed; refusing to append: {result['error']}"
                )

            previous_hash = records[-1]["record_hash"] if records else GENESIS_HASH
            payload = {
                "index": len(records) + 1,
                "id": uuid4().hex,
                "filename": filename,
                "evidence_sha256": evidence_hash,
                "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "previous_hash": previous_hash,
            }
            record = {**payload, "record_hash": self._record_hash(payload)}
            self._write_records([*records, record])
            return record

    def _write_records(self, records: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=".ledger-",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = temporary_file.name
                json.dump(records, temporary_file, indent=2, ensure_ascii=False)
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, self.path)
            temporary_path = None
        except OSError as exc:
            raise LedgerError(f"Could not save the ledger: {exc}") from exc
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass
