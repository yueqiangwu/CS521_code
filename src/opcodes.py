from common import VM_TRUE, VM_FALSE, VMError
from crypto import hash160, verify_sig, verify_multisig, verify_schnorr
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from engine import BitcoinScriptInterpreter


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


@opcode(0x00)
def op_0(vm: "BitcoinScriptInterpreter"):
    vm.push(b"")


def _register_small_ints():
    def create_op_func(i):
        def op_func(vm: "BitcoinScriptInterpreter"):
            vm.push(i.to_bytes(1, "little"))

        return op_func

    for i in range(1, 17):
        code = 0x50 + i
        op_name = f"OP_{i}"
        func = create_op_func(i)

        OP_OPCODE_MAP[op_name] = code
        OPCODE_OP_MAP[code] = op_name
        OPCODE_FUNC_MAP[code] = func

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
    # 32-byte x-only pubkey → BIP340 Schnorr; 33-byte compressed → ECDSA
    if len(pubkey) == 32:
        result = verify_schnorr(pubkey, signature, vm.tx_sig_hash)
    else:
        result = verify_sig(pubkey, signature, vm.tx_sig_hash)
    vm.push(VM_TRUE if result else VM_FALSE)


@opcode(0xBA)
def op_checksigadd(vm: "BitcoinScriptInterpreter"):
    """BIP342 Tapscript: pop pubkey, n, sig; push n+1 if sig valid, n if sig empty, fail otherwise."""
    pubkey = vm.pop()
    n_bytes = vm.pop()
    sig = vm.pop()

    n = int.from_bytes(n_bytes, "little") if n_bytes else 0

    if not sig:
        vm.push(n_bytes)
        return

    if len(pubkey) == 32:
        result = verify_schnorr(pubkey, sig, vm.tx_sig_hash)
    else:
        result = verify_sig(pubkey, sig, vm.tx_sig_hash)

    if not result:
        raise VMError("OP_CHECKSIGADD: non-empty signature failed verification")

    new_n = n + 1
    vm.push(new_n.to_bytes((new_n.bit_length() + 7) // 8, "little"))


@opcode(0xAE)
def op_checkmultisig(vm: "BitcoinScriptInterpreter"):
    n_data = vm.pop()
    n = int.from_bytes(n_data, "little") if n_data else 0

    pubkeys = []
    for _ in range(n):
        pubkeys.append(vm.pop())
    pubkeys.reverse()

    m_data = vm.pop()
    m = int.from_bytes(m_data, "little") if m_data else 0

    signatures = []
    for _ in range(m):
        signatures.append(vm.pop())
    signatures.reverse()

    success = verify_multisig(pubkeys, signatures, vm.tx_sig_hash)

    if success:
        vm.push(VM_TRUE)
    else:
        vm.push(VM_FALSE)
