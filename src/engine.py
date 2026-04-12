from common import VM_FALSE
from opcodes import OPCODES_MAP
from script import Script


class BircoinScriptInterpreter:
    def __init__(self, script: Script, tx_sig_hash=None):
        self.stack = []
        self.script = script
        self.tx_sig_hash = tx_sig_hash
        self.pc = 0

    def push(self, item: bytes):
        self.stack.append(item)

    def pop(self):
        if len(self.stack) < 1:
            raise RuntimeError("Stack underflow")

        return self.stack.pop()

    def top(self):
        if len(self.stack) < 1:
            raise RuntimeError("Empty stack")

        return self.stack[-1]

    def execute(self) -> bool:
        for cmd in self.script.cmds:
            # If it is byte data, push it directly onto the stack.
            if isinstance(cmd, bytes):
                self.push(cmd)

            # If it is an opcode, call the corresponding function from the mapping table.
            elif cmd in OPCODES_MAP.keys():
                func = OPCODES_MAP.get(cmd)
                if func is None:
                    raise RuntimeError("Invalid opcode")

                func(self)

            # Small Constant
            elif 0x51 <= cmd <= 0x60:
                data = (cmd - 0x50).to_bytes(1, "little")
                self.push(data)

            else:
                raise RuntimeError(f"Unknown Opcode: {hex(cmd)}")

        # Verification: The stack top must be non-empty and non-zero
        if len(self.stack) == 0:
            return False

        res = self.top()
        return res != b"" and res != VM_FALSE
