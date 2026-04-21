from common import VMError
from opcodes import op_2_opcode
from crypto import hash160
from engine import BitcoinScriptInterpreter
from script import Script
import logging



def p2wpkh(sig, pubkey, tx_sig_hash) -> bool:
    pubkey_hash = hash160(pubkey)

    script_pubkey_cmds = [0x00, pubkey_hash]  # Witness Version 0  # 20字节的公钥哈希
    script_pubkey = Script(script_pubkey_cmds)

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
        script=script_pubkey, 
        initial_stack=initial_stack, 
        tx_sig_hash=tx_sig_hash
    )
    
    try:
        is_valid = vm.execute()
        print(f"P2SH Validation Result: {is_valid}")
        return is_valid
    except Exception as e:
        print(f"P2SH Execution failed with exception: {e}")
        return False