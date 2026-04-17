import logging
from src.common import op_2_opcode, VMError
from src.crypto import hash160
from src.engine import BitcoinScriptInterpreter
from src.script import Script


OP_DUP = op_2_opcode("OP_DUP")
OP_HASH160 = op_2_opcode("OP_HASH160")
OP_EQUALVERIFY = op_2_opcode("OP_EQUALVERIFY")
OP_CHECKSIG = op_2_opcode("OP_CHECKSIG")
# 假设你的解释器和 hash160 函数在 interpreter.py 中
# from interpreter import BircoinScriptInterpreter, hash160, VMError

def test_p2wpkh_success():
    print("=== Testing P2WPKH Success ===")
    
    # 1. Mock data (模拟交易数据)
    dummy_tx_hash = b"a" * 32
    pubkey = b"dummy_pubkey_33_bytes_long_____" # 真实的公钥通常是 33 字节压缩格式
    sig = b"correct_dummy_signature_71_bytes"   # 真实的签名通常是 71 字节 DER 格式
    
    # 计算公钥哈希 (等效于 OP_HASH160)
    pubkey_hash = hash160(pubkey)

    # 2. 构建 ScriptPubKey (锁定脚本)
    # SegWit P2WPKH 格式: 0x00 <20-byte-hash>
    script_pubkey_cmds = [
        0x00,           # Witness Version 0
        pubkey_hash     # 20字节的公钥哈希
    ]
    script_pubkey = Script(script_pubkey_cmds)

    # 3. 构建 Witness Data (见证数据)
    # P2WPKH 的 witness 栈必须严格包含两个元素：[签名, 公钥]
    witness_data = [
        sig,
        pubkey
    ]

    # 4. 初始化解释器
    # 注意：此时不需要 initial_stack，因为对于 SegWit，参数在 witness 里
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, 
        witness=witness_data, 
        tx_sig_hash=dummy_tx_hash
    )
    
    # 5. 执行并捕获结果
    try:
        # execute() 内部会自动识别这是 SegWit 交易，并调用 _execute_p2wpkh
        is_valid = vm.execute()
        print(f"Result: {is_valid}")
        assert is_valid is True, "P2WPKH validation failed but was expected to succeed."
        logging.info("P2WPKH Test Passed!\n")

    except Exception as e:
        print(f"Test failed with exception: {e}\n")

# 运行测试
if __name__ == "__main__":
    # 配置一下 logging 以便看到 VM 内部的 step 输出
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    dummy_tx_hash = b"a" * 32
    pubkey = b"dummy_pubkey_33_bytes_long_____" # 真实的公钥通常是 33 字节压缩格式
    sig = b"correct_dummy_signature_71_bytes"   # 真实的签名通常是 71 字节 DER 格式
    
    # 计算公钥哈希 (等效于 OP_HASH160)
    pubkey_hash = hash160(pubkey)
