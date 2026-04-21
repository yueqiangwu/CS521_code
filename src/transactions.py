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

def p2sh(signatures, redeem_script, tx_sig_hash) -> bool:
    """
    仿照 p2wpkh 风格的 P2SH 验证函数
    :param signatures: list[bytes], 包含所有必要的签名或参数 (例如 [OP_0, sig1, sig2])
    :param redeem_script: Script, 原始的赎回脚本对象
    :param tx_sig_hash: bytes, 待签名的交易哈希
    """
    # 1. 计算赎回脚本的哈希 (HASH160)
    # 注意：这里需要调用你 Script 类的序列化方法（假设叫 serialize）
    redeem_script_bytes = redeem_script.serialize()
    script_hash = hash160(redeem_script_bytes)

    # 2. 构造 ScriptPubKey (锁定脚本)
    # 格式: OP_HASH160 <20字节哈希> OP_EQUAL
    # 0xa9 是 OP_HASH160, 0x87 是 OP_EQUAL
    script_pubkey_cmds = [0xa9, script_hash, 0x87]
    script_pubkey = Script(script_pubkey_cmds)

    # 3. 构造初始栈 (Initial Stack)
    # P2SH 的解锁逻辑是：先压入签名，最后压入赎回脚本的字节原文
    initial_stack = []
    for s in signatures:
        initial_stack.append(s)
    initial_stack.append(redeem_script_bytes)

    # 4. 初始化解释器
    # 注意：P2SH 使用 initial_stack，而 P2WPKH 使用 witness
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, 
        initial_stack=initial_stack, 
        tx_sig_hash=tx_sig_hash
    )

    try:
        # 执行验证
        # 你的虚拟机在执行完 ScriptPubKey 后，应该会自动触发 handle_p2sh 逻辑
        is_valid = vm.execute()
        print(f"Result: {is_valid}")
        
        # 这里的断言仅用于测试环境
        assert is_valid is True, "P2SH validation failed but was expected to succeed."
        print("P2SH Test Passed!\n")
        return is_valid

    except Exception as e:
        print(f"Test failed with exception: {e}\n")
        return False