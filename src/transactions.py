from common import VMError, generate_p2pkh_script
from opcodes import op_2_opcode
from crypto import hash160, sha256, aggregate_pubkeys
from engine import BitcoinScriptInterpreter
from script import Script
import logging


def p2pkh(sig: bytes, pubkey: bytes, tx_sig_hash: bytes) -> bool:
    pubkey_hash = hash160(pubkey)
    script = Script.parse(generate_p2pkh_script(sig, pubkey, pubkey_hash))
    vm = BitcoinScriptInterpreter(script=script, tx_sig_hash=tx_sig_hash)
    try:
        is_valid = vm.execute()
        print(f"P2PKH Validation Result: {is_valid}")
        return is_valid or False
    except Exception as e:
        print(f"P2PKH Execution failed with exception: {e}")
        return False


def p2wpkh(sig: bytes, pubkey: bytes, tx_sig_hash: bytes) -> bool:
    pubkey_hash = hash160(pubkey)
    script_pubkey = Script.parse(f"OP_0 <{pubkey_hash.hex()}>")
    witness_data = [sig, pubkey]
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=witness_data, tx_sig_hash=tx_sig_hash
    )
    try:
        is_valid = vm.execute()
        print(f"P2WPKH Validation Result: {is_valid}")
        return is_valid or False
    except Exception as e:
        print(f"P2WPKH Execution failed with exception: {e}")
        return False


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

    script_pubkey = Script([0x51, final_pubkey])
    witness_data = [sig]
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=witness_data, tx_sig_hash=tx_sig_hash,
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
    script_pubkey = Script.parse(f"OP_0 <{script_hash.hex()}>")
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
