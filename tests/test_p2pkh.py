from src.common import op_2_opcode, VMError
from src.crypto import hash160
from src.engine import BitcoinScriptInterpreter
from src.script import Script


OP_DUP = op_2_opcode("OP_DUP")
OP_HASH160 = op_2_opcode("OP_HASH160")
OP_EQUALVERIFY = op_2_opcode("OP_EQUALVERIFY")
OP_CHECKSIG = op_2_opcode("OP_CHECKSIG")


def test_p2pkh_success():
    # Mock data
    dummy_tx_hash = b"a" * 32
    pubkey = b"dummy_pubkey"
    pubkey_hash = hash160(pubkey)
    sig = b"correct_sig"

    # Build script (Unlocking + Locking)
    # P2PKH: <sig> <pubkey> OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    full_cmds = [
        sig,
        pubkey,
        OP_DUP,
        OP_HASH160,
        pubkey_hash,
        OP_EQUALVERIFY,
        OP_CHECKSIG,
    ]
    script = Script(full_cmds)

    # Execute script
    vm = BitcoinScriptInterpreter(script, tx_sig_hash=dummy_tx_hash)
    try:
        is_valid = vm.execute()
        print(f"Result: {is_valid}")

    except VMError as e:
        print(e)


if __name__ == "__main__":
    test_p2pkh_success()
