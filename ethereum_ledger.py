"""Web3.py adapter for recording evidence metadata on a local Ethereum chain."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forensic_ledger import LedgerError

HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_RPC_URL = "http://127.0.0.1:7545"
GANACHE_CHAIN_ID = 1337


class EthereumEvidenceLedger:
    """Expose the evidence-ledger interface using an Ethereum smart contract."""

    def __init__(self, web3: Any, contract: Any, account: str):
        self.web3 = web3
        self.contract = contract
        self.account = account

    @classmethod
    def from_environment(cls) -> "EthereumEvidenceLedger":
        from web3 import HTTPProvider, Web3

        project_dir = Path(__file__).resolve().parent
        deployment_path = Path(
            os.environ.get(
                "EVIDENCE_DEPLOYMENT_FILE",
                project_dir / "contract" / "deployment.json",
            )
        )
        rpc_url = os.environ.get("EVIDENCE_RPC_URL", DEFAULT_RPC_URL)
        try:
            deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
            abi = deployment["abi"]
            address = os.environ.get(
                "EVIDENCE_CONTRACT_ADDRESS", deployment["address"]
            )
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LedgerError(
                f"Could not load contract deployment from {deployment_path}: {exc}"
            ) from exc

        try:
            web3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
            if not web3.is_connected():
                raise LedgerError(f"Cannot connect to Ethereum RPC at {rpc_url}.")
            if int(web3.eth.chain_id) != GANACHE_CHAIN_ID:
                raise LedgerError(
                    f"Expected local Ganache chain ID {GANACHE_CHAIN_ID}, "
                    f"but RPC reports {web3.eth.chain_id}."
                )
            accounts = web3.eth.accounts
            configured_account = os.environ.get("EVIDENCE_ACCOUNT")
            if not accounts and not configured_account:
                raise LedgerError("The development node did not expose an unlocked account.")
            account = Web3.to_checksum_address(configured_account or accounts[0])
            if account not in [Web3.to_checksum_address(item) for item in accounts]:
                raise LedgerError(
                    "EVIDENCE_ACCOUNT must be an unlocked account exposed by the "
                    "local development node."
                )
            contract_address = Web3.to_checksum_address(address)
            if not web3.eth.get_code(contract_address):
                raise LedgerError(
                    f"No contract code found at {contract_address}; deploy the "
                    "evidence contract first."
                )
            contract = web3.eth.contract(address=contract_address, abi=abi)
        except LedgerError:
            raise
        except Exception as exc:
            raise LedgerError(f"Could not connect to the evidence contract: {exc}") from exc
        return cls(web3, contract, account)

    def append(self, filename: str, evidence_hash: str) -> dict[str, Any]:
        if not HASH_PATTERN.fullmatch(evidence_hash):
            raise LedgerError("Evidence SHA-256 must be 64 lowercase hexadecimal characters.")
        if not filename or len(filename.encode("utf-8")) > 255:
            raise LedgerError("Filename must contain between 1 and 255 UTF-8 bytes.")

        try:
            transaction_hash = self.contract.functions.registerEvidence(
                bytes.fromhex(evidence_hash), filename
            ).transact({"from": self.account})
            receipt = self.web3.eth.wait_for_transaction_receipt(
                transaction_hash, timeout=120
            )
            self._require_success(receipt, "Evidence registration")
            evidence_id = int(self.contract.functions.getEvidenceCount().call())
            record = self._read_record(evidence_id)
            record["transaction_hash"] = self._hex(transaction_hash)
            record["block_number"] = int(receipt["blockNumber"])
            return record
        except LedgerError:
            raise
        except Exception as exc:
            raise LedgerError(f"Could not register evidence on Ethereum: {exc}") from exc

    def read_records(self) -> list[dict[str, Any]]:
        try:
            count = int(self.contract.functions.getEvidenceCount().call())
            return [self._read_record(index) for index in range(1, count + 1)]
        except LedgerError:
            raise
        except Exception as exc:
            raise LedgerError(f"Could not read evidence records from Ethereum: {exc}") from exc

    def verify(self) -> dict[str, Any]:
        try:
            records = self.read_records()
            for expected_index, record in enumerate(records, start=1):
                if record["index"] != expected_index or not HASH_PATTERN.fullmatch(
                    record["evidence_sha256"]
                ):
                    return {
                        "valid": False,
                        "count": len(records),
                        "error": f"Ethereum evidence record {expected_index} is invalid.",
                    }
            return {"valid": True, "count": len(records), "error": None}
        except LedgerError as exc:
            return {"valid": False, "count": 0, "error": str(exc)}

    def record_custody(self, evidence_id: str | int, action: str) -> dict[str, Any]:
        try:
            index = int(evidence_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("Select an existing evidence record.") from exc
        if index < 1:
            raise ValueError("Select an existing evidence record.")
        if not action or len(action.encode("utf-8")) > 64:
            raise ValueError("Custody action must contain between 1 and 64 UTF-8 bytes.")
        try:
            transaction_hash = self.contract.functions.recordCustody(
                index, action
            ).transact({"from": self.account})
            receipt = self.web3.eth.wait_for_transaction_receipt(
                transaction_hash, timeout=120
            )
            self._require_success(receipt, "Custody update")
            record = self._read_record(index)
            record["transaction_hash"] = self._hex(transaction_hash)
            record["block_number"] = int(receipt["blockNumber"])
            return record
        except LedgerError:
            raise
        except Exception as exc:
            raise LedgerError(f"Could not record custody on Ethereum: {exc}") from exc

    def _read_record(self, index: int) -> dict[str, Any]:
        raw_hash, filename, registered_by, recorded_at = (
            self.contract.functions.getEvidence(index).call()
        )
        custody_count = int(
            self.contract.functions.getCustodyCount(index).call()
        )
        history = []
        for history_index in range(custody_count):
            actor, action, timestamp = self.contract.functions.getCustodyEntry(
                index, history_index
            ).call()
            history.append(
                {
                    "actor": actor,
                    "action": action,
                    "recorded_at": self._timestamp(timestamp),
                }
            )
        return {
            "index": index,
            "id": str(index),
            "filename": filename,
            "evidence_sha256": self._hex(raw_hash),
            "recorded_at": self._timestamp(recorded_at),
            "custodian": registered_by,
            "custody_history": history,
        }

    @staticmethod
    def _timestamp(timestamp: int) -> str:
        return datetime.fromtimestamp(int(timestamp), timezone.utc).isoformat(
            timespec="seconds"
        )

    @staticmethod
    def _hex(value: Any) -> str:
        result = value.hex() if isinstance(value, bytes) else str(value)
        return result.removeprefix("0x").lower()

    @staticmethod
    def _require_success(receipt: Any, operation: str) -> None:
        if int(receipt["status"]) != 1:
            raise LedgerError(f"{operation} transaction failed on Ethereum.")
