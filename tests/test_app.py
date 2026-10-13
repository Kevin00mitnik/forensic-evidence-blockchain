import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from app import create_app
from forensic_ledger import EvidenceLedger, GENESIS_HASH, LedgerError


class EvidenceAppTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temporary_directory.name) / "data"
        self.app = create_app(self.data_dir)
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def register(self, filename="evidence.txt", content=b"original evidence"):
        return self.client.post(
            "/evidence",
            data={"evidence": (io.BytesIO(content), filename)},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    def test_register_stores_hash_and_custody_record(self):
        response = self.register()
        evidence_hash = hashlib.sha256(b"original evidence").hexdigest()
        records = EvidenceLedger(self.data_dir / "ledger.json").read_records()

        self.assertEqual(response.status_code, 200)
        self.assertIn(evidence_hash.encode(), response.data)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["filename"], "evidence.txt")
        self.assertEqual(records[0]["evidence_sha256"], evidence_hash)
        self.assertEqual(records[0]["previous_hash"], GENESIS_HASH)
        self.assertTrue((self.data_dir / "uploads" / f"{evidence_hash}.blob").exists())

    def test_verify_reports_matching_and_mismatching_files(self):
        self.register()
        record = EvidenceLedger(self.data_dir / "ledger.json").read_records()[0]

        matching = self.client.post(
            "/verify",
            data={
                "record_id": record["id"],
                "evidence": (io.BytesIO(b"original evidence"), "copy.txt"),
            },
            follow_redirects=True,
        )
        mismatch = self.client.post(
            "/verify",
            data={
                "record_id": record["id"],
                "evidence": (io.BytesIO(b"changed evidence"), "copy.txt"),
            },
            follow_redirects=True,
        )

        self.assertIn(b"File matches record", matching.data)
        self.assertIn(b"File does not match record", mismatch.data)

    def test_ledger_verification_detects_tampering_and_refuses_append(self):
        self.register()
        ledger_path = self.data_dir / "ledger.json"
        records = json.loads(ledger_path.read_text(encoding="utf-8"))
        records[0]["filename"] = "changed.txt"
        ledger_path.write_text(json.dumps(records), encoding="utf-8")
        ledger = EvidenceLedger(ledger_path)

        self.assertFalse(ledger.verify()["valid"])
        with self.assertRaises(LedgerError):
            ledger.append("another.txt", "a" * 64)

    def test_upload_filename_is_sanitized_and_empty_upload_is_rejected(self):
        self.register(filename="../../evidence.txt")
        records = EvidenceLedger(self.data_dir / "ledger.json").read_records()
        self.assertEqual(records[0]["filename"], "evidence.txt")
        self.assertTrue(
            all(
                path.name == f"{records[0]['evidence_sha256']}.blob"
                for path in (self.data_dir / "uploads").glob("*.blob")
            )
        )

        response = self.register(filename="empty.txt", content=b"")
        self.assertIn(b"Empty evidence files are not accepted", response.data)
        self.assertEqual(len(EvidenceLedger(self.data_dir / "ledger.json").read_records()), 1)

    def test_invalid_record_selection_is_rejected(self):
        response = self.client.post(
            "/verify",
            data={
                "record_id": "not-a-record",
                "evidence": (io.BytesIO(b"file"), "evidence.txt"),
            },
            follow_redirects=True,
        )
        self.assertIn(b"Select an existing ledger record", response.data)

    def test_file_verification_refuses_a_tampered_ledger(self):
        self.register()
        ledger_path = self.data_dir / "ledger.json"
        records = json.loads(ledger_path.read_text(encoding="utf-8"))
        record_id = records[0]["id"]
        records[0]["filename"] = "tampered.txt"
        ledger_path.write_text(json.dumps(records), encoding="utf-8")

        response = self.client.post(
            "/verify",
            data={
                "record_id": record_id,
                "evidence": (io.BytesIO(b"original evidence"), "copy.txt"),
            },
            follow_redirects=True,
        )

        self.assertIn(b"Cannot verify against an invalid ledger", response.data)


if __name__ == "__main__":
    unittest.main()
