from engine import BircoinScriptInterpreter
from opcodes_map import opcode


@opcode(0x76)
def op_dup(vm: BircoinScriptInterpreter):
    data = vm.top()
    vm.stack.append(data)
