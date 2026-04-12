from common import op_2_opcode, VM_TRUE, VM_FALSE, VMError
from crypto import hash160, verify_sig
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engine import BircoinScriptInterpreter


OPCODES_MAP: dict[int, function] = {}


def opcode(func):
    op = func.__name__
    opcode = op_2_opcode(op)
    if opcode is None:
        raise ValueError(f"Unknown operation {op}")

    if opcode in OPCODES_MAP.keys():
        raise ValueError(f"Operation {op} already registered")

    OPCODES_MAP[opcode] = func
    return func


@opcode
def op_dup(vm: "BircoinScriptInterpreter"):
    data = vm.top()
    vm.push(data)


@opcode
def op_hash160(vm: "BircoinScriptInterpreter"):
    data = vm.pop()
    hashed_data = hash160(data)
    vm.push(hashed_data)


@opcode
def op_equal(vm: "BircoinScriptInterpreter"):
    data_1 = vm.pop()
    data_2 = vm.pop()
    if data_1 == data_2:
        vm.push(VM_TRUE)
    else:
        vm.push(VM_FALSE)


@opcode
def op_equalverify(vm: "BircoinScriptInterpreter"):
    op_equal(vm)
    res = vm.pop()
    if res != VM_TRUE:
        raise VMError("OP_EQUALVERIFY failed")


@opcode
def op_checksig(vm: "BircoinScriptInterpreter"):
    pubkey = vm.pop()
    signature = vm.pop()
    if verify_sig(pubkey, signature, vm.tx_sig_hash):
        vm.push(VM_TRUE)
    else:
        vm.push(VM_FALSE)
