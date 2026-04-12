OP_OPCODE_MAP: dict[str, int] = {
    "OP_DUP": 0x76,
    "OP_HASH160": 0xA9,
    "OP_EQUAL": 0x87,
    "OP_EQUALVERIFY": 0xAD,
    "OP_CHECKSIG": 0xAC,
}

def op_2_opcode(op: str):
    return OP_OPCODE_MAP.get(op.upper())


OPCODES_MAP: dict[int, function] = {}


def opcode():
    def decorator(func):
        opcode = op_2_opcode(func.__name__)
        OPCODES_MAP[opcode] = func
        return func

    return decorator


VM_TRUE = b"\x01"
VM_FALSE = b"\x00"


class VMError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return f"Transaction failed: {self.message}"
