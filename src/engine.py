import logging

from common import opcode_2_op, VMError, VM_FALSE
from opcodes import OPCODES_MAP
from script import Script


class BircoinScriptInterpreter:
    def __init__(
        self, script: Script, initial_stack: list | None = None, tx_sig_hash=None
    ):
        self.script = script
        self.stack = initial_stack or []

        self.tx_sig_hash = tx_sig_hash

        self.pc = 0
        self.terminated = False

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

    def step(self):
        if self.terminated:
            logging.info("Execution finished")
            return
        if self.pc >= len(self.script.cmds):
            self.terminated = True
            return

        cmd = self.script.cmds[self.pc]
        if isinstance(cmd, int):
            logging.info(f"Step [{self.pc}] Executing: {opcode_2_op(cmd)}")
        else:
            logging.info(f"Step [{self.pc}] Push Data: {cmd.hex()}")

        # If it is byte data, push it directly onto the stack.
        if isinstance(cmd, bytes):
            self.push(cmd)
        # If it is an opcode, call the corresponding function from the mapping table.
        elif cmd in OPCODES_MAP.keys():
            func = OPCODES_MAP.get(cmd)
            if func is None:
                raise RuntimeError("Invalid opcode")

            try:
                func(self)
            except VMError as e:
                logging.info(f"Invalid transaction: {e.message}")
                self.terminated = True
                raise e
        # Small Constant
        elif 0x51 <= cmd <= 0x60:
            data = (cmd - 0x50).to_bytes(1, "little")
            self.push(data)
        else:
            raise RuntimeError(f"Unknown Opcode: {hex(cmd)}")

        self.pc += 1

    def is_valid(self) -> bool:
        # The stack top must be non-empty and non-zero
        if not self.terminated and len(self.stack) == 0:
            return False

        res = self.top()
        return res != b"" and res != VM_FALSE

    def execute(self) -> bool:
        while not self.terminated:
            self.step()

        return self.is_valid()

    @staticmethod
    def handle_p2sh(vm, redeem_script_bytes, tx_sig_hash):
        """
        For P2SH, creates a new virtual machine to execute the inner script
        """
        logging.info("\nP2SH Pattern Detected! Initializing Inner VM...")
        inner_script = Script.parse(redeem_script_bytes)
        inner_vm = BircoinScriptInterpreter(inner_script, vm.stack, tx_sig_hash)
        return inner_vm.run_all()
