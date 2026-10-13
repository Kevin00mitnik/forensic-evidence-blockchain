"""Compile and deploy EvidenceCustody to a local unlocked development chain."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from solcx import compile_source, get_installed_solc_versions, install_solc
from web3 import HTTPProvider, Web3

PROJECT_DIR = Path(__file__).resolve().parents[1]
CONTRACT_PATH = PROJECT_DIR / "contract" / "EvidenceCustody.sol"
DEPLOYMENT_PATH = Path(
    os.environ.get(
        "EVIDENCE_DEPLOYMENT_FILE",
        PROJECT_DIR / "contract" / "deployment.json",
    )
)
SOLC_VERSION = "0.8.24"
DEFAULT_RPC_URL = "http://127.0.0.1:7545"
GANACHE_CHAIN_ID = 1337


def main() -> int:
    rpc_url = os.environ.get("EVIDENCE_RPC_URL", DEFAULT_RPC_URL)
    web3 = Web3(HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
    if not web3.is_connected():
        print(f"Cannot connect to Ethereum RPC at {rpc_url}. Start Ganache first.", file=sys.stderr)
        return 1
    if int(web3.eth.chain_id) != GANACHE_CHAIN_ID:
        print(
            f"Expected local Ganache chain ID {GANACHE_CHAIN_ID}, "
            f"but RPC reports {web3.eth.chain_id}.",
            file=sys.stderr,
        )
        return 1
    if not web3.eth.accounts:
        print("The development node did not expose an unlocked account.", file=sys.stderr)
        return 1

    if not any(str(version) == SOLC_VERSION for version in get_installed_solc_versions()):
        print(f"Installing Solidity compiler {SOLC_VERSION}...")
        install_solc(SOLC_VERSION)

    source = CONTRACT_PATH.read_text(encoding="utf-8")
    compiled = compile_source(
        source,
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
    )
    _, contract_artifact = next(iter(compiled.items()))
    factory = web3.eth.contract(
        abi=contract_artifact["abi"],
        bytecode=contract_artifact["bin"],
    )
    sender = web3.to_checksum_address(web3.eth.accounts[0])
    transaction_hash = factory.constructor().transact({"from": sender})
    receipt = web3.eth.wait_for_transaction_receipt(transaction_hash, timeout=120)
    if int(receipt["status"]) != 1 or not receipt.get("contractAddress"):
        print("Contract deployment transaction failed.", file=sys.stderr)
        return 1

    deployment = {
        "address": web3.to_checksum_address(receipt["contractAddress"]),
        "abi": contract_artifact["abi"],
        "chain_id": int(web3.eth.chain_id),
    }
    DEPLOYMENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEPLOYMENT_PATH.write_text(
        json.dumps(deployment, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"EvidenceCustody deployed at {deployment['address']}")
    print(f"Deployment details saved to {DEPLOYMENT_PATH}")
    print("Set EVIDENCE_BACKEND=ethereum before starting the Flask app.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
