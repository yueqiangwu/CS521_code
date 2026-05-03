import logging

from common import (
    VMError,
    TransactionType,
    InstructionType,
    VM_FALSE,
    VM_TRUE,
    generate_p2pkh_script,
)
from crypto import hash160, sha256, verify_schnorr
from opcodes import opcode_2_op, is_true, CONTROL_OPS, OPCODE_FUNC_MAP
from script import Script


class BitcoinScriptInterpreterV2:
    def __init__(
        self,
        tx_hash: bytes,
        script_sig: Script,
        script_pubkey: Script,
        witness: Script,
    ):
        self.tx_sig_hash = tx_hash

        self.script_sig = script_sig
        self.script_pubkey = script_pubkey
        self.witness = witness

        self.is_terminated = False
        self.pc = 0
        self.instructions = []
        self.stack = []
        self.alt_stack = []
        self.vf_stack: list[bool] = []

        self.trans_type = TransactionType.LEGACY
        self.instr_types: list[InstructionType] = []

        self._initialize()

    # ========== Transaction helper functions ==========

    def _initialize(self):
        transaction_type = self._predict_transaction_type()
        match transaction_type:
            case TransactionType.P2WPKH:
                logging.info("Executing P2WPKH...")
                self._initialize_p2wpkh()
            case TransactionType.P2WSH:
                logging.info("Executing P2WSH...")
                self._initialize_p2wsh()
            case TransactionType.P2TR:
                logging.info("Executing P2TR...")
                self._initialize_p2tr()
            case TransactionType.P2SH:
                logging.info("Executing P2SH...")
                self._initialize_p2sh()
            case TransactionType.LEGACY:
                logging.info("Executing legacy script...")
                self._initialize_legacy()
            case _:
                raise ValueError(f"Unknown transaction type: {transaction_type}")

        self.trans_type = transaction_type

    def _predict_transaction_type(self) -> TransactionType:
        """
        Check if the scriptPubKey follows SegWit witness or P2SH pattern
        """
        cmds = self.script_pubkey.cmds

        # SegWit witness program
        if (
            len(self.script_sig.cmds) == 0
            and len(cmds) == 2
            and isinstance(cmds[1], bytes)
        ):
            # v0
            if cmds[0] == 0x00:
                if len(cmds[1]) == 20:
                    return TransactionType.P2WPKH
                if len(cmds[1]) == 32:
                    return TransactionType.P2WSH
            # v1
            elif cmds[0] == 0x51:
                if len(cmds[1]) == 32:
                    return TransactionType.P2TR

        # P2SH pattern: OP_HASH160 <20-byte hash> OP_EQUAL
        if len(cmds) == 3 and isinstance(cmds[1], bytes):
            # 0xA9 = OP_HASH160, 0x87 = OP_EQUAL
            if cmds[0] == 0xA9 and cmds[2] == 0x87:
                if len(cmds[1]) == 20:
                    return TransactionType.P2SH

        return TransactionType.LEGACY

    def _initialize_p2wpkh(self):
        if len(self.witness.cmds) != 2:
            raise VMError(
                "P2WPKH requires exactly 2 items in witness (signature, pubkey)"
            )

        sig, pubkey = self.witness.cmds[0], self.witness.cmds[1]
        pubkey_hash = self.script_pubkey.cmds[1]

        # Check pubkey hash matches the one in scriptPubKey
        if hash160(pubkey) != pubkey_hash:
            raise VMError("P2WPKH pubkey hash mismatch")

        # Construct the equivalent P2PKH script
        # <sig> <pubkey> OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        p2pkh_script = generate_p2pkh_script(sig, pubkey, pubkey_hash)
        p2pkh_script_cmds = Script.parse(p2pkh_script).cmds

        self.pc = 2
        self.instructions.extend(self.script_pubkey.cmds)
        self.instructions.extend(p2pkh_script_cmds)
        self.instr_types.extend(InstructionType.DISABLED for _ in range(2))
        self.instr_types.extend(
            InstructionType.WITNESS for _ in range(len(p2pkh_script_cmds))
        )

    def _initialize_p2wsh(self):
        if len(self.witness.cmds) < 1:
            raise VMError("P2WSH requires at least 1 item in witness (witnessScript)")

        witness_script_bytes = self.witness.cmds[-1]
        args = self.witness.cmds[:-1]
        script_hash = self.script_pubkey.cmds[1]

        # Check if the SHA256 hash of the witness script matches the script hash in scriptPubKey
        if sha256(witness_script_bytes) != script_hash:
            raise VMError("P2WSH script hash mismatch")

        witness_script = Script.parse_hex(witness_script_bytes.hex())

        # Execute the witness script with the args as the initial stack
        self.pc = 2
        self.instructions.extend(self.script_pubkey.cmds)
        self.instructions.extend(args)
        self.instructions.extend(witness_script.cmds)
        self.instr_types.extend(InstructionType.DISABLED for _ in range(2))
        self.instr_types.extend(InstructionType.WITNESS_ARG for _ in range(len(args)))
        self.instr_types.extend(
            InstructionType.WITNESS for _ in range(len(witness_script.cmds))
        )

    def _initialize_p2tr(self) -> bool:
        """
        P2TR key-path spend (BIP341): directly verify the Schnorr signature.
        """
        if len(self.witness.cmds) < 1:
            raise VMError("P2TR requires at least 1 witness item (signature)")

        witness_script_bytes = self.witness.cmds[-1]
        args = self.witness.cmds[:-1]
        script_hash = self.script_pubkey.cmds[1]

        # Check if the SHA256 hash of the witness script matches the script hash in scriptPubKey
        if sha256(witness_script_bytes) != script_hash:
            raise VMError("P2WSH script hash mismatch")

        witness_script = Script.parse_hex(witness_script_bytes.hex())

        sig = args[0]
        pubkey = witness_script.cmds[0]

        if verify_schnorr(pubkey, sig, self.tx_sig_hash):
            self.push(VM_TRUE)
        else:
            self.push(VM_FALSE)

        self.is_terminated = True

    def _initialize_p2sh(self) -> bool:
        if len(self.script_sig.cmds) < 1:
            raise VMError("P2SH requires at least 1 item in sig script (redeemScript)")

        redeem_script_bytes = self.script_sig.cmds[-1]
        args = self.script_sig.cmds

        redeem_script = Script.parse_hex(redeem_script_bytes.hex())

        self.instructions.extend(args)
        self.instructions.extend(self.script_pubkey.cmds)
        self.instructions.extend(redeem_script.cmds)
        self.instr_types.extend(InstructionType.SIG for _ in range(len(args)))
        self.instr_types.extend(
            InstructionType.PUBKEY for _ in range(len(self.script_pubkey.cmds))
        )
        self.instr_types.extend(
            InstructionType.REDEEM for _ in range(len(redeem_script.cmds))
        )

    def _initialize_legacy(self):
        self.instructions.extend(self.script_sig.cmds)
        self.instructions.extend(self.script_pubkey.cmds)
        self.instr_types.extend(
            InstructionType.SIG for _ in range(len(self.script_sig.cmds))
        )
        self.instr_types.extend(
            InstructionType.PUBKEY for _ in range(len(self.script_pubkey.cmds))
        )

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

    def is_valid(self) -> bool:
        if not self.is_terminated or len(self.stack) < 1:
            return False

        return is_true(self.top())

    # ========== Execute functions ==========

    def step(self):
        if self.is_terminated:
            logging.info("Execution already finished")
            return

        # Fetch cmd using pc
        cmd = self.instructions[self.pc]
        is_active = all(self.vf_stack)

        if isinstance(cmd, bytes):
            if is_active:
                logging.info(f"Step [{self.pc}] Push Data: {cmd.hex()}")

                self.push(cmd)
        elif cmd in OPCODE_FUNC_MAP.keys():
            if is_active or cmd in CONTROL_OPS:
                logging.info(f"Step [{self.pc}] Executing: {opcode_2_op(cmd)}")

                func = OPCODE_FUNC_MAP[cmd]
                try:
                    func(self)
                except VMError as e:
                    logging.info(f"Transaction failed: {e.message}")

                    self.is_terminated = True
                    raise e
        else:
            raise VMError(f"Unknown Opcode: {hex(cmd)}")

        self.pc += 1
        if self.pc == len(self.instructions):
            self.is_terminated = True

            if self.vf_stack:
                raise VMError("Unbalanced conditional: missing OP_ENDIF")

        if (
            self.trans_type == TransactionType.P2SH
            and self.instr_types[self.pc - 1] == InstructionType.PUBKEY
            and self.instr_types[self.pc] == InstructionType.REDEEM
        ):
            if len(self.stack) < 1 or self.top() != VM_TRUE:
                self.is_terminated = True
            else:
                self.pop()
