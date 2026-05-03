import json
import pytest

from src.engine_v2 import BitcoinScriptInterpreterV2
from src.script import Script
from src.common import VMError

# pytest tests/test_interpreter.py -v > tests/test_interpreter_outputs.txt


def load_test_cases():
    """
    Load and filter valid test cases from script_tests.json
    """
    with open("tests/script_tests.json", "r") as f:
        raw_data = json.load(f)

    test_cases = []
    for entry in raw_data:
        # Skip explanatory string lines
        if len(entry) < 4:
            continue

        # [[witness..., amount]?, scriptSig, scriptPubKey, flags, expected, comments]
        if isinstance(entry[0], list):
            witness_data = entry[0][:-1]
            # amount = entry[0][-1]
            script_sig_str = entry[1]
            script_pubkey_str = entry[2]
            flags = entry[3]
            expected = entry[4]
        else:
            witness_data = []
            script_sig_str = entry[0]
            script_pubkey_str = entry[1]
            flags = entry[2]
            expected = entry[3]

        test_cases.append(
            (witness_data, script_sig_str, script_pubkey_str, flags, expected)
        )
    return test_cases


@pytest.mark.parametrize(
    "witness_data, sig_str, pubkey_str, flags, expected", load_test_cases()
)
def test_bitcoin_core_vectors(witness_data, sig_str, pubkey_str, flags, expected):
    """
    Run Bitcoin Core Standard Test Vectors
    """
    # 1. Prepare scripts
    try:
        script_sig = Script.parse_asm(sig_str)
        script_pubkey = Script.parse_asm(pubkey_str)

        witness_cmds = []
        for item in witness_data:
            if item.startswith("#SCRIPT#"):
                witness_cmds.append(Script.parse_asm(item).serialize().hex())
            elif item.startswith("#CONTROLBLOCK#"):
                pass
            else:
                witness_cmds.append(bytes.fromhex(item))
        witness_script = Script(witness_cmds)

    except Exception as e:
        if expected == "OK":
            pytest.fail(f"Failed to parse ASM: {e}")
        return

    # 2. Initialize interpreter
    dummy_tx_hash = b"\x00" * 32

    interpreter = BitcoinScriptInterpreterV2(
        tx_hash=dummy_tx_hash,
        script_sig=script_sig,
        script_pubkey=script_pubkey,
        witness=witness_script,
    )

    # 3. Execute script
    try:
        while not interpreter.is_terminated:
            interpreter.step()

        # 4. Verification results
        success = interpreter.is_valid()

        if expected == "OK":
            assert (
                success is True
            ), f"Expected OK, but script failed. Stack: {interpreter.stack}"
        else:
            assert success is False, f"Expected {expected}, but script passed."

    except VMError as e:
        if expected == "OK":
            pytest.fail(f"Execution failed for valid script: {e.message}")
        else:
            pass
    except Exception as e:
        if expected == "OK":
            pytest.fail(f"Unexpected Python error: {e}")
