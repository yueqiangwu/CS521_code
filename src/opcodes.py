from common import opcode, VM_TRUE, VM_FALSE, VMError
from crypto import hash160, verify_sig
from engine import BircoinScriptInterpreter


@opcode
def op_dup(vm: BircoinScriptInterpreter):
    data = vm.top()
    vm.push(data)


@opcode
def op_hash160(vm: BircoinScriptInterpreter):
    data = vm.pop()
    hashed_data = hash160(data)
    vm.push(hashed_data)


@opcode
def op_equal(vm: BircoinScriptInterpreter):
    data_1 = vm.pop()
    data_2 = vm.pop()
    if data_1 == data_2:
        vm.push(VM_TRUE)
    else:
        vm.push(VM_FALSE)


@opcode
def op_equalverify(vm: BircoinScriptInterpreter):
    op_equal(vm)
    res = vm.pop()
    if res != VM_TRUE:
        raise VMError("OP_EQUALVERIFY failed")


@opcode
def op_checksig(vm: BircoinScriptInterpreter):
    pubkey = vm.pop()
    signature = vm.pop()
    if verify_sig(pubkey, signature, vm.tx_sig_hash):
        vm.push(VM_TRUE)
    else:
        vm.push(VM_FALSE)
