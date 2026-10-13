import hashlib
import io
import unittest
import tempfile
from pathlib import Path

from app import create_app
from ethereum_ledger import EthereumEvidenceLedger
from forensic_ledger import LedgerError


class FakeFunction:
    def __init__(self, call=None, transact=None):
        self._call = call
        self._transact = transact

    def call(self):
        return self._call()

    def transact(self, transaction):
        return self._transact(transaction)


class FakeContract:
    def __init__(self, web3):
        self.web3 = web3
        self.entries = {}
        self.functions = self

    def getEvidenceCount(self):
        return FakeFunction(call=lambda: len(self.entries))

    def getEvidence(self, index):
        return FakeFunction(
            call=lambda: (
                self._evidence(index)["file_hash"],
                self._evidence(index)["filename"],
                self._evidence(index)["registered_by"],
                self._evidence(index)["registered_at"],
            )
        )

    def getCustodyCount(self, index):
        return FakeFunction(call=lambda: len(self._evidence(index)["history"]))

    def getCustodyEntry(self, index, history_index):
        return FakeFunction(
            call=lambda: self._evidence(index)["history"][history_index]
        )

    def registerEvidence(self, file_hash, filename):
        def submit(_transaction):
            index = len(self.entries) + 1
            self.entries[index] = {
                "file_hash": file_hash,
                "filename": filename,
                "registered_by": "0x" + "1" * 40,
                "registered_at": 1_700_000_000,
                "history": [
                    ("0x" + "1" * 40, "REGISTERED", 1_700_000_000)
                ],
            }
            return self.web3.eth.submit()

        return FakeFunction(transact=submit)

    def recordCustody(self, index, action):
        def submit(_transaction):
            evidence = self._evidence(index)
            evidence["history"].append(
                ("0x" + "2" * 40, action, 1_700_000_100)
            )
            return self.web3.eth.submit()

        return FakeFunction(transact=submit)

    def _evidence(self, index):
        if index not in self.entries:
            raise ValueError("Unknown evidence")
        return self.entries[index]


class FakeEth:
    def __init__(self):
        self.block_number = 0
        self.receipts = {}

    def submit(self):
        self.block_number += 1
        transaction_hash = "0x" + f"{self.block_number:064x}"
        self.receipts[transaction_hash] = {
            "status": 1,
            "blockNumber": self.block_number,
        }
        return transaction_hash

    def wait_for_transaction_receipt(self, transaction_hash, timeout):
        return self.receipts[transaction_hash]


class FakeWeb3:
    def __init__(self):
        self.eth = FakeEth()


class EthereumEvidenceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.web3 = FakeWeb3()
        self.contract = FakeContract(self.web3)
        self.ledger = EthereumEvidenceLedger(
            self.web3, self.contract, "0x" + "1" * 40
        )

    def test_register_reads_on_chain_record_and_registration_history(self):
        expected_hash = hashlib.sha256(b"evidence bytes").hexdigest()

        record = self.ledger.append("photo.jpg", expected_hash)

        self.assertEqual(record["index"], 1)
        self.assertEqual(record["filename"], "photo.jpg")
        self.assertEqual(record["evidence_sha256"], expected_hash)
        self.assertEqual(record["custody_history"][0]["action"], "REGISTERED")
        self.assertEqual(record["block_number"], 1)
        self.assertTrue(self.ledger.verify()["valid"])

    def test_custody_updates_are_read_from_contract(self):
        record = self.ledger.append("report.txt", "a" * 64)

        updated = self.ledger.record_custody(record["id"], "SEALED")

        self.assertEqual(len(updated["custody_history"]), 2)
        self.assertEqual(updated["custody_history"][1]["action"], "SEALED")
        self.assertEqual(updated["custody_history"][1]["actor"], "0x" + "2" * 40)

    def test_rejects_invalid_hash_and_unknown_custody_record(self):
        with self.assertRaises(ValueError):
            self.ledger.record_custody("not-an-id", "RECEIVED")
        with self.assertRaises(LedgerError):
            self.ledger.append("photo.jpg", "not-a-sha256")

    def test_ethereum_routes_register_verify_and_record_history(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            app = create_app(
                Path(temporary_directory),
                evidence_service=self.ledger,
                backend="ethereum",
            )
            app.config["TESTING"] = True
            client = app.test_client()
            registered = client.post(
                "/evidence",
                data={"evidence": (io.BytesIO(b"route evidence"), "sample.txt")},
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            evidence_hash = hashlib.sha256(b"route evidence").hexdigest()
            self.assertIn(evidence_hash.encode(), registered.data)
            self.assertIn(b"REGISTERED", registered.data)

            verified = client.post(
                "/verify",
                data={
                    "record_id": "1",
                    "evidence": (io.BytesIO(b"route evidence"), "copy.txt"),
                },
                content_type="multipart/form-data",
                follow_redirects=True,
            )
            self.assertIn(b"File matches record", verified.data)

            custody = client.post(
                "/custody",
                data={"record_id": "1", "action": "TRANSFERRED"},
                follow_redirects=True,
            )
            self.assertIn(b"TRANSFERRED", custody.data)
            self.assertIn(b"Custody action transferred recorded on Ethereum", custody.data)

            invalid_action = client.post(
                "/custody",
                data={"record_id": "1", "action": "private note"},
                follow_redirects=True,
            )
            self.assertIn(b"Choose a valid custody action", invalid_action.data)


if __name__ == "__main__":
    unittest.main()
