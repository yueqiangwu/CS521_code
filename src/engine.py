import hashlib
import logging

from common import VMError, VM_FALSE, generate_p2pkh_script
from crypto import hash160, verify_sig
from opcodes import opcode_2_op, OPCODE_FUNC_MAP
from script import Script


class BitcoinScriptInterpreter:
    def __init__(
        self,
        script: Script,
        initial_stack: list | None = None,
        witness: list | None = None,
        tx_sig_hash: bytes | None = None,
    ):
        self.script = script
        self.stack = initial_stack or []
        self.witness = witness or []

        self.tx_sig_hash = tx_sig_hash

        self.pc = 0
        self.terminated = False
        self.active_inner_vm = None  # P2SH/SegWit

    def push(self, item: bytes):
        self.stack.append(item)

    def pop(self):
        if len(self.stack) < 1:
            raise VMError("Stack underflow")

        return self.stack.pop()

    def top(self):
        if len(self.stack) < 1:
            raise VMError("Empty stack")

        return self.stack[-1]

    def step(self):
        if self.terminated:
            logging.info("Execution finished")
            return

        if self.active_inner_vm is not None:
            self.active_inner_vm.step()

            if self.active_inner_vm.terminated:
                self.active_inner_vm = None

                res = self.active_inner_vm.is_valid()
                if not res:
                    raise VMError("Inner VM execution failed")

                self.terminated = True

            return

        if self.pc >= len(self.script.cmds):
            self.terminated = True
            return

        cmd = self.script.cmds[self.pc]
        if isinstance(cmd, int):
            logging.info(f"Step [{self.pc}] Executing: {opcode_2_op(cmd)}")
        else:
            logging.info(f"Step [{self.pc}] Push Data: {cmd.hex()}")

        if self.pc == 0 and self._is_witness_program():
            self._setup_witness_vm()
            return

        if isinstance(cmd, bytes):
            self.push(cmd)
        elif cmd in OPCODE_FUNC_MAP.keys():
            func = OPCODE_FUNC_MAP[cmd]

            try:
                func(self)
            except VMError as e:
                logging.info(f"Invalid transaction: {e.message}")
                self.terminated = True
                raise e
        elif 0x51 <= cmd <= 0x60:
            data = (cmd - 0x50).to_bytes(1, "little")
            self.push(data)
        else:
            raise VMError(f"Unknown Opcode: {hex(cmd)}")

        self.pc += 1

    def execute(self) -> bool:
        # Check if it's a SegWit transaction by inspecting the scriptPubKey pattern
        if self._is_witness_program():
            logging.info("\nSegWit Pattern Detected!")
            is_valid = self._execute_witness_program()
            self.terminated = True
            return is_valid

        # Traditional Legacy
        while not self.terminated:
            self.step()

        return self.is_valid()

    def is_valid(self) -> bool:
        if not self.terminated:
            return False

        if len(self.stack) == 0:
            return False

        res = self.top()
        return res != b"" and res != VM_FALSE

    def _is_witness_program(self) -> bool:
        """
        Check if the scriptPubKey matches the SegWit pattern: 0x00 + 20 bytes/32 bytes
        """
        cmds = self.script.cmds

        if len(cmds) == 2 and cmds[0] == 0x00 and isinstance(cmds[1], bytes):
            if len(cmds[1]) == 20 or len(cmds[1]) == 32:
                return True
        return False

    def _setup_witness_vm(self):
        """
        Initialize the SegWit sub-virtual machine
        """
        program = self.script.cmds[1]

        # P2WPKH
        if len(program) == 20:
            sig, pubkey = self.witness[0], self.witness[1]
            p2pkh_cmds = generate_p2pkh_script(sig, pubkey, program)
            self.active_inner_vm = BitcoinScriptInterpreter(
                Script(p2pkh_cmds), tx_sig_hash=self.tx_sig_hash
            )
        # P2WSH
        elif len(program) == 32:
            witness_script_bytes = self.witness[-1]
            args = self.witness[:-1]
            self.active_inner_vm = BitcoinScriptInterpreter(
                Script.parse(witness_script_bytes),
                initial_stack=args,
                tx_sig_hash=self.tx_sig_hash,
            )

    def _execute_witness_program(self) -> bool:
        """Divide P2WPKH and P2WSH"""
        cmds = self.script.cmds
        program = cmds[1]

        if len(program) == 20:
            logging.info("Executing P2WPKH...")
            return self._execute_p2wpkh(program)
        elif len(program) == 32:
            logging.info("Executing P2WSH...")
            return self._execute_p2wsh(program)
        else:
            raise VMError("Invalid witness program length")

    def _execute_p2wpkh(self, pubkey_hash: bytes) -> bool:
        if len(self.witness) != 2:
            raise VMError(
                "P2WPKH requires exactly 2 items in witness (signature, pubkey)"
            )

        sig, pubkey = self.witness[0], self.witness[1]

        # Check pubkey hash matches the one in scriptPubKey
        if hash160(pubkey) != pubkey_hash:
            raise VMError("P2WPKH pubkey hash mismatch")

        # Construct the equivalent P2PKH script
        # <sig> <pubkey> OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        p2pkh_cmds = generate_p2pkh_script(sig, pubkey, pubkey_hash)
        inner_script = Script(p2pkh_cmds)
        inner_vm = BitcoinScriptInterpreter(inner_script, tx_sig_hash=self.tx_sig_hash)

        while not inner_vm.terminated:
            inner_vm.step()

        return inner_vm.is_valid()

    def _execute_p2wsh(self, script_hash: bytes) -> bool:
        if len(self.witness) == 0:
            raise VMError("P2WSH requires at least 1 item in witness (witnessScript)")

        witness_script_bytes = self.witness[-1]
        args = self.witness[:-1]

        # Check if the SHA256 hash of the witness script matches the script hash in scriptPubKey
        if hashlib.sha256(witness_script_bytes).digest() != script_hash:
            raise VMError("P2WSH script hash mismatch")

        # Execute the witness script in a new VM instance, with the args as the initial stack
        inner_script = Script.parse(witness_script_bytes)
        inner_vm = BitcoinScriptInterpreter(
            inner_script, initial_stack=args, tx_sig_hash=self.tx_sig_hash
        )

        while not inner_vm.terminated:
            inner_vm.step()
        return inner_vm.is_valid()
