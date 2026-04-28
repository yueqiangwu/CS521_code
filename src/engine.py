import hashlib
import logging

from common import VMError, VM_FALSE, generate_p2pkh_script, VM_TRUE
from crypto import hash160, verify_sig, verify_schnorr
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

    # ========== Tool functions ==========

    def push(self, item):
        self.stack.append(item)

    def pop(self):
        if len(self.stack) < 1:
            raise VMError("Stack underflow")

        return self.stack.pop()

    def top(self):
        if len(self.stack) < 1:
            raise VMError("Empty stack")

        return self.stack[-1]

    # ========== Execute functions ==========

    def step(self):
        if self.terminated:
            logging.info("Execution already finished")
            return

        # Execute inner vm first
        if self.active_inner_vm is not None:
            self.active_inner_vm.step()

            if self.active_inner_vm.terminated:
                res = self.active_inner_vm._is_valid()
                if not res:
                    raise VMError("Inner VM execution failed")

                self.push(VM_TRUE)
                self.pc = len(self.script.cmds)
                self.terminated = True
                self.active_inner_vm = None
            return

        # Check if it's a SegWit transaction
        if self.pc == 0 and self._is_witness_program():
            logging.info("\nSegWit Pattern Detected!")

            self._execute_witness_program(step_mode=True)
            return

        # Fetch cmd using pc
        cmd = self.script.cmds[self.pc]
        if isinstance(cmd, bytes):
            logging.info(f"Step [{self.pc}] Push Data: {cmd.hex()}")

            self.push(cmd)
        elif cmd in OPCODE_FUNC_MAP.keys():
            logging.info(f"Step [{self.pc}] Executing: {opcode_2_op(cmd)}")

            func = OPCODE_FUNC_MAP[cmd]
            try:
                func(self)
            except VMError as e:
                logging.info(f"Transaction failed: {e.message}")

                self.terminated = True
                raise e
        else:
            raise VMError(f"Unknown Opcode: {hex(cmd)}")

        self.pc += 1
        if self.pc == len(self.script.cmds):
            self.terminated = True

        # Check if it's a P2SH transaction
        if self.terminated and self._is_valid() and self._is_p2sh_pattern():
            logging.info(
                "\nPhase 1 (Fingerprint Verification) Passed, Preparing to Execute P2SH Phase 2!"
            )

            redeem_script_bytes = self.pop()
            self._execute_p2sh(redeem_script_bytes, self.stack, step_mode=True)
            self.terminated = False

    def execute(self) -> bool:
        if self.terminated:
            logging.info("Execution already finished")
            return

        # Check if it's a SegWit transaction by inspecting the scriptPubKey pattern
        if self._is_witness_program():
            logging.info("\nSegWit Pattern Detected!")

            return self._execute_witness_program()

        # Traditional legacy
        while not self.terminated:
            self.step()

        # Check if it's a P2SH transaction
        if self._is_valid() and self._is_p2sh_pattern():
            logging.info(
                "\nPhase 1 (Fingerprint Verification) Passed, Preparing to Execute P2SH Phase 2!"
            )

            redeem_script_bytes = self.pop()

            return self._execute_p2sh(redeem_script_bytes, self.stack)

        return self._is_valid()

    # ========== Transaction check functions ==========

    def _is_valid(self) -> bool:
        if not self.terminated or len(self.stack) == 0:
            return False

        res = self.top()
        return res != b"" and res != VM_FALSE

    def _is_witness_program(self) -> bool:
        """Check if the scriptPubKey is a SegWit witness program (v0 or v1/P2TR)."""
        cmds = self.script.cmds
        if len(cmds) != 2 or not isinstance(cmds[1], bytes):
            return False
        # SegWit v0: OP_0 + 20 bytes (P2WPKH) or 32 bytes (P2WSH)
        if (cmds[0] == b'\x00' or cmds[0] == 0x00) and len(cmds[1]) in (20, 32):
            return True
        # SegWit v1: OP_1 (0x51) + 32 bytes (P2TR)
        if cmds[0] == 0x51 and len(cmds[1]) == 32:
            return True
        return False


    def _is_p2sh_pattern(self) -> bool:
        """
        Check if the scriptPubKey is a P2SH pattern: OP_HASH160 <20-byte hash> OP_EQUAL
        """
        cmds = self.script.cmds
        # 0xA9 = OP_HASH160, 0x87 = OP_EQUAL
        return len(cmds) == 3 and cmds[0] == 0xA9 and cmds[2] == 0x87

    def _execute_witness_program(self, step_mode: bool = False) -> bool:
        """Dispatch to P2WPKH, P2WSH, or P2TR based on witness version and program length."""
        cmds = self.script.cmds
        version = cmds[0]
        program = cmds[1]

        if version == 0x51:
            # SegWit v1 — P2TR (key-path spend)
            logging.info("Executing P2TR...")
            return self._execute_p2tr(program)

        # SegWit v0
        if len(program) == 20:
            logging.info("Executing P2WPKH...")
            return self._execute_p2wpkh(program, step_mode)
        elif len(program) == 32:
            logging.info("Executing P2WSH...")
            return self._execute_p2wsh(program, step_mode)
        else:
            raise VMError("Invalid witness program length")

    def _execute_p2wpkh(self, pubkey_hash: bytes, step_mode: bool = False) -> bool:
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
        inner_script = Script.parse(p2pkh_cmds)
        inner_vm = BitcoinScriptInterpreter(inner_script, tx_sig_hash=self.tx_sig_hash)

        if step_mode:
            self.active_inner_vm = inner_vm
            return True

        while not inner_vm.terminated:
            inner_vm.step()

        return inner_vm._is_valid()

    def _execute_p2wsh(self, script_hash: bytes, step_mode: bool = False) -> bool:
        if len(self.witness) == 0:
            raise VMError("P2WSH requires at least 1 item in witness (witnessScript)")

        witness_script_bytes = self.witness[-1]
        args = self.witness[:-1]

        # Check if the SHA256 hash of the witness script matches the script hash in scriptPubKey
        if hashlib.sha256(witness_script_bytes).digest() != script_hash:
            raise VMError("P2WSH script hash mismatch")

        # Execute the witness script in a new VM instance, with the args as the initial stack
        try:
            inner_script = Script.parse(witness_script_bytes.hex())
        except Exception as e:
            logging.error(f"P2WSH inner script parsing failed: {e}")
            return False

        inner_vm = BitcoinScriptInterpreter(
            inner_script, initial_stack=args, tx_sig_hash=self.tx_sig_hash
        )

        if step_mode:
            self.active_inner_vm = inner_vm
            return True

        while not inner_vm.terminated:
            inner_vm.step()
        return inner_vm.is_valid()
    
    def _execute_p2tr(self, pubkey: bytes) -> bool:
        """P2TR key-path spend (BIP341): directly verify the Schnorr signature."""
        if len(self.witness) == 0:
            raise VMError("P2TR requires at least 1 witness item (signature)")

        sig = self.witness[0]
        return verify_schnorr(pubkey, sig, self.tx_sig_hash)


    def _execute_p2sh(
        self, redeem_script_bytes: bytes, inner_stack: list, step_mode: bool = False
    ) -> bool:
        try:
            inner_script = Script.parse_hex(redeem_script_bytes.hex())
        except Exception as e:
            logging.error(f"P2SH inner script parsing failed: {e}")
            return False

        inner_vm = BitcoinScriptInterpreter(
            script=inner_script, initial_stack=inner_stack, tx_sig_hash=self.tx_sig_hash
        )

        if step_mode:
            self.active_inner_vm = inner_vm
            return True

        while not inner_vm.terminated:
            inner_vm.step()

        return inner_vm._is_valid()

        # try:
        #     is_valid = inner_vm.execute()

        #     if is_valid:
        #         logging.info("=== P2SH Inner VM Validation Passed! ===")
        #     else:
        #         logging.warning("=== P2SH Inner VM Validation Failed! ===")

        #     return is_valid

        # except Exception as e:
        #     logging.error(f"P2SH Inner VM Execution Error: {e}")
        #     return False
