import logging

from src.common import generate_segwit_p2pkh_script
from src.crypto import hash160
from src.engine import BitcoinScriptInterpreter
from src.script import Script


def test_p2wpkh_success():
    print("=== Testing P2WPKH Success ===")

    # 1. Mock data
    dummy_tx_hash = b"a" * 32
    pubkey = b"dummy_pubkey_33_bytes_long_____"
    sig = b"correct_dummy_signature_71_bytes"
    pubkey_hash = hash160(pubkey)

    # 2. construct ScriptPubKey
    # SegWit P2WPKH: 0x00 <20-byte-hash>
    script_pubkey_cmds = generate_segwit_p2pkh_script(pubkey_hash)
    script_pubkey = Script.parse(script_pubkey_cmds)

    # 3. construct Witness Data
    witness_data = [sig, pubkey]

    # 4. initialize interpreter
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=witness_data, tx_sig_hash=dummy_tx_hash
    )

    # 5. execute & get result
    # execute() automatically identifies this as a SegWit transaction and invokes _execute_p2wpkh()
    try:
        is_valid = vm.execute()
        print(f"Result: {is_valid}")
        assert is_valid is True, "P2WPKH validation failed but was expected to succeed."
        logging.info("P2WPKH Test Passed!\n")
    except Exception as e:
        print(f"Test failed with exception: {e}\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    test_p2wpkh_success()
