from common import VMError
from opcodes import op_2_opcode
from crypto import hash160
from engine import BitcoinScriptInterpreter
from script import Script
import logging

OP_DUP = op_2_opcode("OP_DUP")
OP_HASH160 = op_2_opcode("OP_HASH160")
OP_EQUALVERIFY = op_2_opcode("OP_EQUALVERIFY")
OP_CHECKSIG = op_2_opcode("OP_CHECKSIG")


def p2wpkh(sig, pubkey, tx_sig_hash) -> bool:
    pubkey_hash = hash160(pubkey)

    # 2. 构建 ScriptPubKey (锁定脚本)
    # SegWit P2WPKH 格式: 0x00 <20-byte-hash>
    script_pubkey_cmds = [0x00, pubkey_hash]  # Witness Version 0  # 20字节的公钥哈希
    script_pubkey = Script(script_pubkey_cmds)

    # 3. 构建 Witness Data (见证数据)
    # P2WPKH 的 witness 栈必须严格包含两个元素：[签名, 公钥]
    witness_data = [sig, pubkey]

    # 4. 初始化解释器
    # 注意：此时不需要 initial_stack，因为对于 SegWit，参数在 witness 里
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=witness_data, tx_sig_hash=tx_sig_hash
    )

    # 5. 执行并捕获结果
    try:
        # execute() 内部会自动识别这是 SegWit 交易，并调用 _execute_p2wpkh
        is_valid = vm.execute()
        print(f"Result: {is_valid}")
        assert is_valid is True, "P2WPKH validation failed but was expected to succeed."
        print("P2WPKH Test Passed!\n")

    except Exception as e:
        print(f"Test failed with exception: {e}\n")
