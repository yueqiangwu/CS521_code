from src.common import VMError, generate_p2pkh_script
from src.crypto import hash160
from src.engine import BitcoinScriptInterpreter
from src.script import Script


def test_p2pkh_success():
    # Mock data
    dummy_tx_hash = b"a" * 32
    pubkey = b"dummy_pubkey"
    pubkey_hash = hash160(pubkey)
    sig = b"correct_sig"

    # Build script (Unlocking + Locking)
    # P2PKH: <sig> <pubkey> OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    full_cmds = generate_p2pkh_script(sig, pubkey, pubkey_hash)
    script = Script.parse(full_cmds)

    # Execute script
    vm = BitcoinScriptInterpreter(script, tx_sig_hash=dummy_tx_hash)
    try:
        is_valid = vm.execute()
        print(f"Result: {is_valid}")

    except VMError as e:
        print(e)


if __name__ == "__main__":
    test_p2pkh_success()
