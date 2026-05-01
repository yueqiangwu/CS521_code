import hashlib
import logging
from dataclasses import dataclass, field

from script import Script
from engine import BitcoinScriptInterpreter
from common import VMError


# ── Helpers ───────────────────────────────────────────────────────────────

def _sha256d(data: bytes) -> bytes:
    """Bitcoin double-SHA256 (used for txid)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _encode_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _serialize_script_items(items: list[bytes]) -> bytes:
    """Serialize a list of push items as a Bitcoin scriptSig byte string."""
    out = b""
    for item in items:
        n = len(item)
        if n < 0x4C:
            out += bytes([n]) + item
        elif n <= 0xFF:
            out += bytes([0x4C, n]) + item
        else:
            out += bytes([0x4D]) + n.to_bytes(2, "little") + item
    return out


# ── Core data types ───────────────────────────────────────────────────────

@dataclass
class UTXO:
    """An unspent transaction output — the basic unit of Bitcoin value."""
    txid: bytes           # 32-byte transaction ID of the creating transaction
    vout: int             # Output index within that transaction
    amount: int           # Value in satoshis
    script_pubkey: Script # Locking script (determines who can spend this)


@dataclass
class TxInput:
    """
    A transaction input that references (and spends) a UTXO.

    script_sig : list of bytes items pushed onto the stack (empty for SegWit)
    witness    : witness stack items (empty for legacy)
    """
    txid: bytes
    vout: int
    script_sig: list[bytes] = field(default_factory=list)
    witness:    list[bytes] = field(default_factory=list)
    sequence:   int = 0xFFFFFFFF


@dataclass
class TxOutput:
    """A transaction output that creates a new UTXO."""
    amount: int           # Value in satoshis
    script_pubkey: Script # Locking script


# ── Transaction ───────────────────────────────────────────────────────────

class Transaction:
    """
    A Bitcoin transaction: consumes UTXOs via inputs and creates new UTXOs
    via outputs.
    """

    def __init__(
        self,
        inputs: list[TxInput],
        outputs: list[TxOutput],
        version: int = 1,
        locktime: int = 0,
    ):
        self.version  = version
        self.inputs   = inputs
        self.outputs  = outputs
        self.locktime = locktime
        self._txid: bytes | None = None

    @property
    def txid(self) -> bytes:
        """Transaction ID: double-SHA256 of the serialized transaction."""
        if self._txid is None:
            self._txid = _sha256d(self._serialize())
        return self._txid

    def sighash(self, input_idx: int, utxo_script_pubkey: Script) -> bytes:
        """
        Legacy (P2PKH / P2SH) signature hash — SIGHASH_ALL.
        NOT suitable for SegWit inputs; use sighash_segwit() for those.
        """
        data = self.version.to_bytes(4, "little")

        data += _encode_varint(len(self.inputs))
        for i, inp in enumerate(self.inputs):
            data += inp.txid
            data += inp.vout.to_bytes(4, "little")
            if i == input_idx:
                sp = utxo_script_pubkey.serialize()
                data += _encode_varint(len(sp)) + sp
            else:
                data += b"\x00"  # empty scriptSig for other inputs
            data += inp.sequence.to_bytes(4, "little")

        data += _encode_varint(len(self.outputs))
        for out in self.outputs:
            data += out.amount.to_bytes(8, "little")
            sp = out.script_pubkey.serialize()
            data += _encode_varint(len(sp)) + sp

        data += self.locktime.to_bytes(4, "little")
        data += (1).to_bytes(4, "little")  # SIGHASH_ALL

        return hashlib.sha256(data).digest()

    def sighash_segwit(self, input_idx: int, script_code: bytes, amount: int) -> bytes:
        """
        BIP143 sighash for SegWit inputs (SIGHASH_ALL).

        script_code:
          P2WPKH       — equivalent P2PKH script: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
          P2WSH        — the witnessScript bytes
        amount: satoshi value of the UTXO being spent
        """
        # hashPrevouts = SHA256d(all outpoints)
        prevouts = b"".join(
            inp.txid + inp.vout.to_bytes(4, "little") for inp in self.inputs
        )
        hash_prevouts = _sha256d(prevouts)

        # hashSequence = SHA256d(all nSequence)
        sequences = b"".join(
            inp.sequence.to_bytes(4, "little") for inp in self.inputs
        )
        hash_sequence = _sha256d(sequences)

        # hashOutputs = SHA256d(all serialized outputs)
        outputs_raw = b""
        for out in self.outputs:
            sp = out.script_pubkey.serialize()
            outputs_raw += out.amount.to_bytes(8, "little") + _encode_varint(len(sp)) + sp
        hash_outputs = _sha256d(outputs_raw)

        inp = self.inputs[input_idx]
        data  = self.version.to_bytes(4, "little")
        data += hash_prevouts
        data += hash_sequence
        data += inp.txid + inp.vout.to_bytes(4, "little")
        data += _encode_varint(len(script_code)) + script_code
        data += amount.to_bytes(8, "little")
        data += inp.sequence.to_bytes(4, "little")
        data += hash_outputs
        data += self.locktime.to_bytes(4, "little")
        data += (1).to_bytes(4, "little")  # SIGHASH_ALL

        return _sha256d(data)

    def _serialize(self) -> bytes:
        """Full transaction serialization (used for txid computation)."""
        data = self.version.to_bytes(4, "little")

        data += _encode_varint(len(self.inputs))
        for inp in self.inputs:
            data += inp.txid
            data += inp.vout.to_bytes(4, "little")
            ss = _serialize_script_items(inp.script_sig)
            data += _encode_varint(len(ss)) + ss
            data += inp.sequence.to_bytes(4, "little")

        data += _encode_varint(len(self.outputs))
        for out in self.outputs:
            data += out.amount.to_bytes(8, "little")
            sp = out.script_pubkey.serialize()
            data += _encode_varint(len(sp)) + sp

        data += self.locktime.to_bytes(4, "little")
        return data


# ── Sighash dispatch ─────────────────────────────────────────────────────

def _compute_sighash(tx: "Transaction", idx: int, inp: TxInput, utxo: UTXO) -> bytes:
    """
    Choose the correct sighash algorithm for an input:
      - Native P2WPKH  → BIP143, scriptCode = equivalent P2PKH script
      - Native P2WSH   → BIP143, scriptCode = witnessScript (witness[-1])
      - Everything else → legacy sighash (P2PKH, P2SH)
    """
    cmds = utxo.script_pubkey.cmds
    v    = cmds[0] if cmds else None
    is_op0 = v == 0x00 or v == b'\x00'

    # Native P2WPKH: OP_0 + 20-byte hash
    if len(cmds) == 2 and is_op0 and isinstance(cmds[1], bytes) and len(cmds[1]) == 20:
        h           = cmds[1]
        script_code = bytes([0x76, 0xa9, 0x14]) + h + bytes([0x88, 0xac])
        return tx.sighash_segwit(idx, script_code, utxo.amount)

    # Native P2WSH: OP_0 + 32-byte hash
    if len(cmds) == 2 and is_op0 and isinstance(cmds[1], bytes) and len(cmds[1]) == 32:
        script_code = inp.witness[-1] if inp.witness else b""
        return tx.sighash_segwit(idx, script_code, utxo.amount)

    # Legacy (P2PKH, regular P2SH, P2TR, …)
    return tx.sighash(idx, utxo.script_pubkey)


# ── Script execution helper ───────────────────────────────────────────────

def _execute_input(inp: TxInput, utxo: UTXO, sig_hash: bytes) -> bool:
    """
    Run the input's unlocking data against the UTXO's locking script.

    Routes to the correct engine path:
      Legacy / P2PKH / P2SH : script_sig items become the initial stack
      SegWit (P2WPKH/P2WSH/P2TR) : witness items are passed as witness
    """
    try:
        vm = BitcoinScriptInterpreter(
            script=utxo.script_pubkey,
            initial_stack=list(inp.script_sig) if inp.script_sig else None,
            witness=list(inp.witness) if inp.witness else None,
            tx_sig_hash=sig_hash,
        )
        return vm.execute() or False
    except (VMError, Exception):
        return False


# ── UTXO Set ──────────────────────────────────────────────────────────────

class UTXOSet:
    """
    The set of all currently unspent transaction outputs.

    Internally keyed by (txid, vout) for O(1) lookup.
    """

    def __init__(self):
        self._utxos: dict[tuple[bytes, int], UTXO] = {}

    # ── Read operations ──────────────────────────────────────────────────

    def get(self, txid: bytes, vout: int) -> UTXO | None:
        return self._utxos.get((txid, vout))

    def contains(self, txid: bytes, vout: int) -> bool:
        return (txid, vout) in self._utxos

    @property
    def size(self) -> int:
        return len(self._utxos)

    def all_utxos(self) -> list[UTXO]:
        return list(self._utxos.values())

    # ── Write operations ─────────────────────────────────────────────────

    def add(self, utxo: UTXO) -> None:
        key = (utxo.txid, utxo.vout)
        if key in self._utxos:
            raise ValueError(
                f"UTXO {utxo.txid.hex()}:{utxo.vout} already exists in the set"
            )
        self._utxos[key] = utxo

    def remove(self, txid: bytes, vout: int) -> None:
        key = (txid, vout)
        if key not in self._utxos:
            raise KeyError(f"UTXO {txid.hex()}:{vout} not found")
        del self._utxos[key]

    # ── Coinbase helper ───────────────────────────────────────────────────

    def add_coinbase(self, txid: bytes, outputs: list[TxOutput]) -> None:
        """Add UTXOs from a coinbase transaction (no input validation needed)."""
        for vout, out in enumerate(outputs):
            self.add(UTXO(txid=txid, vout=vout,
                          amount=out.amount, script_pubkey=out.script_pubkey))

    # ── Validation ────────────────────────────────────────────────────────

    def validate(self, tx: Transaction) -> tuple[bool, str]:
        """
        Validate a transaction against the current UTXO set.

        Checks (in order):
          1. Every input references an existing UTXO.
          2. No two inputs spend the same UTXO (intra-transaction double-spend).
          3. Total output value ≤ total input value (no inflation).
          4. Every input's script validates against its UTXO's scriptPubKey.

        Returns (True, "valid") on success, (False, <reason>) on failure.
        """
        # 1. Resolve input UTXOs
        input_utxos: list[UTXO] = []
        for i, inp in enumerate(tx.inputs):
            utxo = self.get(inp.txid, inp.vout)
            if utxo is None:
                return False, (
                    f"input {i}: UTXO {inp.txid.hex()}:{inp.vout} not found"
                )
            input_utxos.append(utxo)

        # 2. Detect intra-transaction double-spend
        seen: set[tuple[bytes, int]] = set()
        for i, inp in enumerate(tx.inputs):
            key = (inp.txid, inp.vout)
            if key in seen:
                return False, f"input {i}: double-spend within transaction"
            seen.add(key)

        # 3. Value conservation
        total_in  = sum(u.amount for u in input_utxos)
        total_out = sum(o.amount for o in tx.outputs)
        if total_out > total_in:
            return False, (
                f"output value {total_out} exceeds input value {total_in}"
            )

        # 4. Script validation for each input
        for i, (inp, utxo) in enumerate(zip(tx.inputs, input_utxos)):
            sig_hash = _compute_sighash(tx, i, inp, utxo)
            if not _execute_input(inp, utxo, sig_hash):
                return False, f"input {i}: script validation failed"

        return True, "valid"

    # ── State transition ──────────────────────────────────────────────────

    def apply(self, tx: Transaction) -> None:
        """
        Apply a (pre-validated) transaction: remove spent UTXOs and add new ones.
        Does NOT re-validate — call validate() first if needed.
        """
        for inp in tx.inputs:
            self.remove(inp.txid, inp.vout)
        for vout, out in enumerate(tx.outputs):
            self.add(UTXO(
                txid=tx.txid,
                vout=vout,
                amount=out.amount,
                script_pubkey=out.script_pubkey,
            ))

    def validate_and_apply(self, tx: Transaction) -> tuple[bool, str]:
        """Validate then atomically apply a transaction."""
        ok, msg = self.validate(tx)
        if ok:
            self.apply(tx)
            logging.info(f"Transaction {tx.txid.hex()} applied: "
                         f"{len(tx.inputs)} input(s) spent, "
                         f"{len(tx.outputs)} output(s) created")
        else:
            logging.warning(f"Transaction rejected: {msg}")
        return ok, msg
