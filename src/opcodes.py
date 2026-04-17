from common import VM_TRUE, VM_FALSE, VMError
from crypto import hash160, verify_sig
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engine import BitcoinScriptInterpreter


OP_OPCODE_MAP: dict[str, int] = {}
OPCODE_OP_MAP: dict[int, str] = {}

OPCODE_FUNC_MAP: dict[int, function] = {}


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
