import logging
import pytest
from src.script import Script
from src.engine import BitcoinScriptInterpreter
from src.transactions import p2wsh
from src.crypto import hash160, sha256


def test_p2wsh_multisig_function():
    logging.info("=== Running P2WSH Multisig Test (Explicit Values via Wrapper) ===")

    dummy_tx_hash = bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    pubkey1 = bytes.fromhex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    )
    pubkey2 = bytes.fromhex(
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
    )

    sig1 = bytes.fromhex(
        "5f2e7c6aab160abcb2b88d98b9e038b6805bf74ebad8d9b9eb3468df22e8ab1b5f287f04e1d3d03205ae1eea91e732a194015765df74cb59b1fdf55eed1df27b01"
    )

    witness_asm = f"OP_1 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    witness_script = Script.parse(witness_asm)

    signatures = [b"", sig1]

    try:
        is_valid = p2wsh(signatures, witness_script, dummy_tx_hash)
        logging.info(f"Validation Result: {is_valid}")
        assert (
            is_valid is True
        ), "P2WSH failed to validate the correct witness script and signature"
        logging.info("P2WSH wrapper test passed!\n")

    except Exception as e:
        pytest.fail(f"Error occurred: {e}")
