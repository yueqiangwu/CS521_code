from src.common import VMError
from src.opcodes import op_2_opcode
from src.crypto import hash160
from src.engine import BitcoinScriptInterpreter
from src.script import Script
import pytest
import logging


def test_p2sh_multisig_explicit():

    logging.info("=== Running P2SH Multisig Test (Explicit Values) ===")

    dummy_tx_hash = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    pubkey1 = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    pubkey2 = bytes.fromhex("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a")
    

    sig1 = bytes.fromhex("422d127175294489c288295b0c849955dd0b4baa533a3c3f17ff8eb2e4cf80b06c29a4e3999b3c5810eb02dbc46516367e27dad6accc8fa1b94d1fa03fe6944201")

    # ==========================================
    # 2. Construct (Redeem Script)
    # ==========================================
    redeem_asm = f"OP_1 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    redeem_script = Script.parse(redeem_asm)
    
    redeem_script_bytes = redeem_script.serialize()
    
    # ==========================================
    # 3. Construct (ScriptPubKey)
    # ==========================================
    script_hash = hash160(redeem_script_bytes)
    
    pubkey_asm = f"OP_HASH160 <{script_hash.hex()}> OP_EQUAL"
    script_pubkey = Script.parse(pubkey_asm)

    initial_stack = [b'', sig1, redeem_script_bytes]


    vm = BitcoinScriptInterpreter(
        script=script_pubkey, 
        initial_stack=initial_stack, 
        tx_sig_hash=dummy_tx_hash
    )

    try:
        is_valid = vm.execute()
        logging.info(f"Validation Result: {is_valid}")
        assert is_valid is True, "P2SH failed to validate the correct redeem script and signature"
        logging.info("ASM construction test passed!\n")

    except Exception as e:
        pytest.fail(f"Error occurred: {e}")

def test_p2sh_tampered_script_fails():

    logging.info("=== Running Tampered Redeem Script Test (Expected to Fail) ===")
    dummy_tx_hash = b"a" * 32


    dummy_pubkey_hex = b"dummy_pubkey".hex()
    correct_script_asm = f"OP_1 <{dummy_pubkey_hex}> OP_1 OP_CHECKMULTISIG"
    correct_script = Script.parse(correct_script_asm)
    correct_hash = hash160(correct_script.serialize())
    
    pubkey_asm = f"OP_HASH160 <{correct_hash.hex()}> OP_EQUAL"
    script_pubkey = Script.parse(pubkey_asm)
    
    malicious_script_asm = "OP_1"
    malicious_script_bytes = Script.parse(malicious_script_asm).serialize()
    
    initial_stack = [b'', b'fake_sig', malicious_script_bytes]
    
    # 5. 执行验证
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, 
        initial_stack=initial_stack, 
        tx_sig_hash=dummy_tx_hash
    )
    
    # 预期结果：OP_HASH160 计算 malicious_script_bytes 的哈希时，
    # 会发现它与锁定脚本里的 correct_hash 对不上，因此 OP_EQUAL 失败，返回 False
    assert vm.execute() is False
    logging.info("Tampered script interception test passed!\n")