from common import VMError
from opcodes import op_2_opcode
from crypto import hash160, sha256, aggregate_pubkeys
from engine import BitcoinScriptInterpreter
from script import Script
import logging


def p2wpkh(sig, pubkey, tx_sig_hash) -> bool:
    pubkey_hash = hash160(pubkey)

    script_pubkey_cmds = [0x00, pubkey_hash]
    script_pubkey = Script.parse(script_pubkey_cmds)

    witness_data = [sig, pubkey]

    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=witness_data, tx_sig_hash=tx_sig_hash
    )

    try:
        is_valid = vm.execute()
        print(f"Result: {is_valid}")
        assert is_valid is True, "P2WPKH validation failed but was expected to succeed."
        print("P2WPKH Test Passed!\n")

    except Exception as e:
        print(f"Test failed with exception: {e}\n")


def p2sh(signatures: list[bytes], redeem_script: Script, tx_sig_hash: bytes) -> bool:

    redeem_script_bytes = redeem_script.serialize()

    script_hash = hash160(redeem_script_bytes)

    pubkey_asm = f"OP_HASH160 <{script_hash.hex()}> OP_EQUAL"
    script_pubkey = Script.parse(pubkey_asm)

    initial_stack = signatures + [redeem_script_bytes]

    vm = BitcoinScriptInterpreter(
        script=script_pubkey, initial_stack=initial_stack, tx_sig_hash=tx_sig_hash
    )

    try:
        is_valid = vm.execute()
        print(f"P2SH Validation Result: {is_valid}")
        return is_valid
    except Exception as e:
        print(f"P2SH Execution failed with exception: {e}")
        return False


def p2tr(sig: bytes, pubkeys: list[bytes], tx_sig_hash: bytes) -> bool:
    """
    P2TR key-path spend (BIP341 / Taproot).

    pubkeys       : one or more 32-byte x-only public keys.
                    Single key  → used directly as the scriptPubKey key.
                    Multiple keys → MuSig-style aggregation via aggregate_pubkeys().
    sig           : 64-byte Schnorr signature (or 65 bytes with sighash-type appended)
    tx_sig_hash   : 32-byte BIP341 transaction signature hash
    """
    if len(pubkeys) == 1:
        final_pubkey = pubkeys[0]
    else:
        final_pubkey = aggregate_pubkeys(pubkeys)

    # scriptPubKey: OP_1 <32-byte-x-only-pubkey>
    script_pubkey = Script([0x51, final_pubkey])

    # Witness stack for key-path spend contains only the signature
    witness_data = [sig]

    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        witness=witness_data,
        tx_sig_hash=tx_sig_hash,
    )

    try:
        is_valid = vm.execute()
        print(f"P2TR Validation Result: {is_valid}")
        return is_valid
    except Exception as e:
        print(f"P2TR Execution failed with exception: {e}")
        return False


def p2wsh(signatures: list[bytes], witness_script: Script, tx_sig_hash: bytes) -> bool:

    witness_script_bytes = witness_script.serialize()

    script_hash = sha256(witness_script_bytes)

    pubkey_asm = f"OP_0 <{script_hash.hex()}>"
    script_pubkey = Script.parse(pubkey_asm)

    witness_data = signatures + [witness_script_bytes]

    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=witness_data, tx_sig_hash=tx_sig_hash
    )

    try:
        is_valid = vm.execute()
        print(f"P2WSH Validation Result: {is_valid}")
        return is_valid
    except Exception as e:
        print(f"P2WSH Execution failed with exception: {e}")
        return False
