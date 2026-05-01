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
        Compute the 32-byte signature hash for a specific input (SIGHASH_ALL).

        Follows simplified Bitcoin signing serialization:
          - All inputs included; for the input being signed, substitute the
            UTXO's scriptPubKey; all other inputs get an empty scriptSig.
          - All outputs included as-is.
          - Append SIGHASH_ALL type (4 bytes LE).
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
            sig_hash = tx.sighash(i, utxo.script_pubkey)
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
