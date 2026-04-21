from common import VM_TRUE, VM_FALSE, VMError
from crypto import hash160, verify_sig, verify_multisig
from typing import TYPE_CHECKING, Callable
import logging
if TYPE_CHECKING:
    from engine import BitcoinScriptInterpreter

# 修正：Function 类型在 typing 中应为 Callable
OP_OPCODE_MAP: dict[str, int] = {}
OPCODE_OP_MAP: dict[int, str] = {}
OPCODE_FUNC_MAP: dict[int, Callable] = {}

def op_2_opcode(op: str) -> int | None:
    return OP_OPCODE_MAP.get(op.upper())

def opcode_2_op(opcode: int) -> str | None:
    return OPCODE_OP_MAP.get(opcode)

def opcode(code: int):
    def wrapper(func):
        if code in OPCODE_OP_MAP.keys() or code in OPCODE_FUNC_MAP.keys():
            raise ValueError(f"Opcode {code} already registered")

        op = func.__name__
        op = op.upper()
        
        if op in OP_OPCODE_MAP.keys():
            raise ValueError(f"Operation {op} already registered")

        OP_OPCODE_MAP[op] = code
        OPCODE_OP_MAP[code] = op
        OPCODE_FUNC_MAP[code] = func

        return func
    return wrapper

# --- 基础操作码实现 ---

@opcode(0x00)
def op_0(vm: "BitcoinScriptInterpreter"):
    """OP_0 / OP_FALSE: 推入空字节"""
    vm.push(b"")

# 批量注册 OP_1 到 OP_16 (0x51 - 0x60)
def _register_small_ints():
    def create_op_func(i):
        def op_func(vm: "BitcoinScriptInterpreter"):
            vm.push(i.to_bytes(1, "little"))
        return op_func

    for i in range(1, 17):
        code = 0x50 + i
        op_name = f"OP_{i}"
        func = create_op_func(i)
        
        # 手动注册到映射表中，以便 parse 方法能识别字符串 "OP_1" 等
        OP_OPCODE_MAP[op_name] = code
        OPCODE_OP_MAP[code] = op_name
        OPCODE_FUNC_MAP[code] = func
        
        # OP_1 特别别名 OP_TRUE
        if i == 1:
            OP_OPCODE_MAP["OP_TRUE"] = code

_register_small_ints()

@opcode(0x76)
def op_dup(vm: "BitcoinScriptInterpreter"):
    data = vm.top()
    vm.push(data)

@opcode(0xA9)
def op_hash160(vm: "BitcoinScriptInterpreter"):
    data = vm.pop()
    hashed_data = hash160(data)
    vm.push(hashed_data)

@opcode(0x87)
def op_equal(vm: "BitcoinScriptInterpreter"):
    data_1 = vm.pop()
    data_2 = vm.pop()
    if data_1 == data_2:
        vm.push(VM_TRUE)
    else:
        vm.push(VM_FALSE)

@opcode(0xAD)
def op_equalverify(vm: "BitcoinScriptInterpreter"):
    op_equal(vm)
    res = vm.pop()
    if res != VM_TRUE:
        raise VMError("OP_EQUALVERIFY failed")

@opcode(0xAC)
def op_checksig(vm: "BitcoinScriptInterpreter"):
    pubkey = vm.pop()
    signature = vm.pop()
    if verify_sig(pubkey, signature, vm.tx_sig_hash):
        vm.push(VM_TRUE)
    else:
        vm.push(VM_FALSE)

@opcode(0xAE)
def op_checkmultisig(vm: "BitcoinScriptInterpreter"):
    # 1. 弹出公钥总数 n
    n_data = vm.pop()
    # 注意：在比特币脚本中，n 可能通过 OP_1..OP_16 推入，
    # 此时 n_data 为 b'\x01' 等。如果是空(OP_0)，则为 0。
    n = int.from_bytes(n_data, "little") if n_data else 0
    
    pubkeys = []
    for _ in range(n):
        pubkeys.append(vm.pop())
    pubkeys.reverse()
    
    # 2. 弹出所需签名数 m
    m_data = vm.pop()
    m = int.from_bytes(m_data, "little") if m_data else 0
    
    signatures = []
    for _ in range(m):
        signatures.append(vm.pop())
    signatures.reverse()
    

    # 3. 弹出那个著名的多签 Dummy Bug 元素 (OP_0)
    _dummy = vm.pop()

    # 4. 核心验证逻辑
    success = verify_multisig(pubkeys, signatures, vm.tx_sig_hash)

    if success:
        vm.push(VM_TRUE)
    else:
        vm.push(VM_FALSE)