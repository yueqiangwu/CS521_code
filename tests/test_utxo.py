"""
UTXO model tests.

Each test builds transactions from scratch, signs them with real keys,
and verifies the UTXOSet behaves correctly.
"""
import logging
import hashlib
from ecdsa import SigningKey, SECP256k1

from src.script import Script
from src.crypto import hash160, sha256
from src.utxo import UTXO, TxInput, TxOutput, Transaction, UTXOSet


# ── Signing helpers ───────────────────────────────────────────────────────

def _ecdsa_sign(private_key_int: int, msg: bytes) -> tuple[bytes, bytes]:
    """Return (pubkey_64bytes, sig_with_sighash) — uses sign_digest."""
    sk = SigningKey.from_string(private_key_int.to_bytes(32, "big"), curve=SECP256k1)
    pubkey = sk.get_verifying_key().to_string()
    sig    = sk.sign_digest(msg) + b"\x01"
    return pubkey, sig


def _p2pkh_script_pubkey(pubkey: bytes) -> Script:
    pubkey_hash = hash160(pubkey)
    return Script.parse(
        f"OP_DUP OP_HASH160 <{pubkey_hash.hex()}> OP_EQUALVERIFY OP_CHECKSIG"
    )


def _p2wpkh_script_pubkey(pubkey: bytes) -> Script:
    return Script.parse(f"OP_0 <{hash160(pubkey).hex()}>")


def _p2wsh_multisig_script_pubkey(m: int, pubkeys: list[bytes]) -> tuple[Script, Script]:
    """Return (scriptPubKey, witness_script)."""
    n = len(pubkeys)
    pk_items       = " ".join(f"<{pk.hex()}>" for pk in pubkeys)
    witness_script = Script.parse(f"OP_{m} {pk_items} OP_{n} OP_CHECKMULTISIG")
    witness_script_bytes = witness_script.serialize()
    script_pubkey  = Script.parse(f"OP_0 <{sha256(witness_script_bytes).hex()}>")
    return script_pubkey, witness_script


PRIVKEY_1 = 1
PRIVKEY_2 = 2

# A fake coinbase txid (nothing to reference before the first UTXO)
GENESIS_TXID = b"\x00" * 32


# ── UTXOSet basic operations ──────────────────────────────────────────────

def test_utxoset_add_and_get():
    logging.info("=== UTXOSet: add and get ===")
    pubkey, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    utxo = UTXO(
        txid=GENESIS_TXID, vout=0,
        amount=100_000,
        script_pubkey=_p2pkh_script_pubkey(pubkey),
    )
    us = UTXOSet()
    us.add(utxo)
    assert us.size == 1
    assert us.contains(GENESIS_TXID, 0)
    assert us.get(GENESIS_TXID, 0) is utxo
    assert us.get(GENESIS_TXID, 1) is None
    logging.info("UTXOSet add/get test passed!\n")


def test_utxoset_remove():
    logging.info("=== UTXOSet: remove ===")
    pubkey, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    us = UTXOSet()
    us.add(UTXO(GENESIS_TXID, 0, 50_000, _p2pkh_script_pubkey(pubkey)))
    us.remove(GENESIS_TXID, 0)
    assert us.size == 0
    assert not us.contains(GENESIS_TXID, 0)
    logging.info("UTXOSet remove test passed!\n")


def test_utxoset_coinbase():
    logging.info("=== UTXOSet: coinbase creation ===")
    pubkey, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    outputs = [
        TxOutput(50_000, _p2pkh_script_pubkey(pubkey)),
        TxOutput(30_000, _p2pkh_script_pubkey(pubkey)),
    ]
    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, outputs)
    assert us.size == 2
    assert us.get(GENESIS_TXID, 0).amount == 50_000
    assert us.get(GENESIS_TXID, 1).amount == 30_000
    logging.info("Coinbase test passed!\n")


# ── P2PKH transaction ─────────────────────────────────────────────────────

def test_p2pkh_spend_valid():
    logging.info("=== P2PKH: valid spend ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    # Fund: coinbase gives 100_000 sat to pubkey1
    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, _p2pkh_script_pubkey(pubkey1))])

    # Build unsigned transaction: spend to pubkey2, change back to pubkey1
    tx = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[
            TxOutput(60_000, _p2pkh_script_pubkey(pubkey2)),
            TxOutput(39_000, _p2pkh_script_pubkey(pubkey1)),  # 1_000 sat fee
        ],
    )

    # Sign: compute sighash, sign with privkey1
    utxo      = us.get(GENESIS_TXID, 0)
    sig_hash  = tx.sighash(0, utxo.script_pubkey)
    _, sig1   = _ecdsa_sign(PRIVKEY_1, sig_hash)

    # Populate scriptSig: [sig, pubkey]
    tx.inputs[0].script_sig = [sig1, pubkey1]

    ok, msg = us.validate_and_apply(tx)
    logging.info(f"Validation Result: {ok} — {msg}")
    assert ok is True, msg

    # Old UTXO gone, two new UTXOs created
    assert not us.contains(GENESIS_TXID, 0)
    assert us.size == 2
    assert us.get(tx.txid, 0).amount == 60_000
    assert us.get(tx.txid, 1).amount == 39_000
    logging.info("P2PKH valid spend test passed!\n")


def test_p2pkh_spend_wrong_sig():
    logging.info("=== P2PKH: wrong signature rejected ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, _p2pkh_script_pubkey(pubkey1))])

    tx = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[TxOutput(90_000, _p2pkh_script_pubkey(pubkey2))],
    )
    utxo = us.get(GENESIS_TXID, 0)
    sig_hash = tx.sighash(0, utxo.script_pubkey)
    # Sign with the WRONG private key
    _, wrong_sig = _ecdsa_sign(PRIVKEY_2, sig_hash)
    tx.inputs[0].script_sig = [wrong_sig, pubkey1]

    ok, msg = us.validate(tx)
    logging.info(f"Validation Result: {ok} — {msg}")
    assert ok is False
    assert us.size == 1  # UTXO not consumed
    logging.info("P2PKH wrong-sig rejected test passed!\n")


def test_p2pkh_double_spend():
    logging.info("=== P2PKH: double-spend rejected ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, _p2pkh_script_pubkey(pubkey1))])

    # First spend: valid
    tx1 = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[TxOutput(90_000, _p2pkh_script_pubkey(pubkey2))],
    )
    utxo = us.get(GENESIS_TXID, 0)
    _, sig1 = _ecdsa_sign(PRIVKEY_1, tx1.sighash(0, utxo.script_pubkey))
    tx1.inputs[0].script_sig = [sig1, pubkey1]
    ok1, _ = us.validate_and_apply(tx1)
    assert ok1 is True

    # Second spend: UTXO already consumed
    tx2 = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[TxOutput(90_000, _p2pkh_script_pubkey(pubkey1))],
    )
    tx2.inputs[0].script_sig = [sig1, pubkey1]
    ok2, msg2 = us.validate(tx2)
    logging.info(f"Double-spend Result: {ok2} — {msg2}")
    assert ok2 is False
    logging.info("Double-spend rejected test passed!\n")


def test_intra_tx_double_spend():
    logging.info("=== P2PKH: intra-transaction double-spend rejected ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, _p2pkh_script_pubkey(pubkey1))])

    # Two inputs referencing the same UTXO
    tx = Transaction(
        inputs=[
            TxInput(txid=GENESIS_TXID, vout=0),
            TxInput(txid=GENESIS_TXID, vout=0),
        ],
        outputs=[TxOutput(180_000, _p2pkh_script_pubkey(pubkey1))],
    )
    ok, msg = us.validate(tx)
    logging.info(f"Result: {ok} — {msg}")
    assert ok is False
    logging.info("Intra-tx double-spend rejected test passed!\n")


def test_inflation_rejected():
    logging.info("=== Value: outputs exceed inputs rejected ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, _p2pkh_script_pubkey(pubkey1))])

    tx = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[TxOutput(200_000, _p2pkh_script_pubkey(pubkey2))],  # more than input
    )
    utxo = us.get(GENESIS_TXID, 0)
    _, sig = _ecdsa_sign(PRIVKEY_1, tx.sighash(0, utxo.script_pubkey))
    tx.inputs[0].script_sig = [sig, pubkey1]

    ok, msg = us.validate(tx)
    logging.info(f"Result: {ok} — {msg}")
    assert ok is False
    assert "exceeds" in msg
    logging.info("Inflation rejected test passed!\n")


# ── P2WPKH transaction ────────────────────────────────────────────────────

def test_p2wpkh_spend_valid():
    logging.info("=== P2WPKH: valid spend ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, _p2wpkh_script_pubkey(pubkey1))])

    tx = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[TxOutput(90_000, _p2wpkh_script_pubkey(pubkey2))],
    )

    utxo     = us.get(GENESIS_TXID, 0)
    sig_hash = tx.sighash(0, utxo.script_pubkey)
    _, sig1  = _ecdsa_sign(PRIVKEY_1, sig_hash)

    # SegWit: scriptSig is empty, signature goes in witness
    tx.inputs[0].witness = [sig1, pubkey1]

    ok, msg = us.validate_and_apply(tx)
    logging.info(f"Validation Result: {ok} — {msg}")
    assert ok is True, msg
    assert us.size == 1
    logging.info("P2WPKH valid spend test passed!\n")


def test_p2wpkh_wrong_pubkey():
    logging.info("=== P2WPKH: wrong pubkey rejected ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, _p2wpkh_script_pubkey(pubkey1))])

    tx = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[TxOutput(90_000, _p2wpkh_script_pubkey(pubkey2))],
    )
    utxo = us.get(GENESIS_TXID, 0)
    _, sig = _ecdsa_sign(PRIVKEY_1, tx.sighash(0, utxo.script_pubkey))
    # Provide pubkey2 in witness even though scriptPubKey commits to pubkey1
    tx.inputs[0].witness = [sig, pubkey2]

    ok, msg = us.validate(tx)
    logging.info(f"Result: {ok} — {msg}")
    assert ok is False
    logging.info("P2WPKH wrong-pubkey rejected test passed!\n")


# ── P2WSH transaction ─────────────────────────────────────────────────────

def test_p2wsh_2of2_spend_valid():
    logging.info("=== P2WSH 2-of-2: valid spend ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    sp_script, witness_script = _p2wsh_multisig_script_pubkey(2, [pubkey1, pubkey2])
    witness_script_bytes      = witness_script.serialize()

    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, sp_script)])

    tx = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[TxOutput(90_000, _p2pkh_script_pubkey(pubkey1))],
    )

    utxo      = us.get(GENESIS_TXID, 0)
    sig_hash  = tx.sighash(0, utxo.script_pubkey)
    _, sig1   = _ecdsa_sign(PRIVKEY_1, sig_hash)
    _, sig2   = _ecdsa_sign(PRIVKEY_2, sig_hash)

    # witness: [dummy, sig1, sig2, witness_script_bytes]
    tx.inputs[0].witness = [b"", sig1, sig2, witness_script_bytes]

    ok, msg = us.validate_and_apply(tx)
    logging.info(f"Validation Result: {ok} — {msg}")
    assert ok is True, msg
    logging.info("P2WSH 2-of-2 valid spend test passed!\n")


def test_p2wsh_missing_sig():
    logging.info("=== P2WSH 2-of-2: missing second signature rejected ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    sp_script, witness_script = _p2wsh_multisig_script_pubkey(2, [pubkey1, pubkey2])
    witness_script_bytes      = witness_script.serialize()

    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, sp_script)])

    tx = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[TxOutput(90_000, _p2pkh_script_pubkey(pubkey1))],
    )
    utxo     = us.get(GENESIS_TXID, 0)
    _, sig1  = _ecdsa_sign(PRIVKEY_1, tx.sighash(0, utxo.script_pubkey))

    # Only one sig provided for a 2-of-2 → should fail
    tx.inputs[0].witness = [b"", sig1, witness_script_bytes]

    ok, msg = us.validate(tx)
    logging.info(f"Result: {ok} — {msg}")
    assert ok is False
    logging.info("P2WSH missing-sig rejected test passed!\n")


# ── Multi-input transaction ───────────────────────────────────────────────

def test_multi_input_transaction():
    logging.info("=== Multi-input: two P2PKH inputs, one output ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    # Two separate UTXOs from different transactions
    txid_a = b"\xaa" * 32
    txid_b = b"\xbb" * 32
    us = UTXOSet()
    us.add(UTXO(txid_a, 0, 60_000, _p2pkh_script_pubkey(pubkey1)))
    us.add(UTXO(txid_b, 0, 40_000, _p2pkh_script_pubkey(pubkey2)))

    # Combine both into one output
    tx = Transaction(
        inputs=[
            TxInput(txid=txid_a, vout=0),
            TxInput(txid=txid_b, vout=0),
        ],
        outputs=[TxOutput(95_000, _p2pkh_script_pubkey(pubkey1))],  # 5_000 fee
    )

    # Sign each input with its respective key
    utxo_a   = us.get(txid_a, 0)
    utxo_b   = us.get(txid_b, 0)
    _, sig_a = _ecdsa_sign(PRIVKEY_1, tx.sighash(0, utxo_a.script_pubkey))
    _, sig_b = _ecdsa_sign(PRIVKEY_2, tx.sighash(1, utxo_b.script_pubkey))

    tx.inputs[0].script_sig = [sig_a, pubkey1]
    tx.inputs[1].script_sig = [sig_b, pubkey2]

    ok, msg = us.validate_and_apply(tx)
    logging.info(f"Validation Result: {ok} — {msg}")
    assert ok is True, msg
    assert us.size == 1  # both consumed, one output created
    assert us.get(tx.txid, 0).amount == 95_000
    logging.info("Multi-input transaction test passed!\n")


# ── Chain of transactions ─────────────────────────────────────────────────

def test_transaction_chain():
    logging.info("=== Chain: tx1 output spent by tx2 ===")

    pubkey1, _ = _ecdsa_sign(PRIVKEY_1, b"\x00" * 32)
    pubkey2, _ = _ecdsa_sign(PRIVKEY_2, b"\x00" * 32)

    us = UTXOSet()
    us.add_coinbase(GENESIS_TXID, [TxOutput(100_000, _p2pkh_script_pubkey(pubkey1))])

    # tx1: pubkey1 → pubkey2
    tx1 = Transaction(
        inputs=[TxInput(txid=GENESIS_TXID, vout=0)],
        outputs=[TxOutput(90_000, _p2pkh_script_pubkey(pubkey2))],
    )
    _, sig1 = _ecdsa_sign(PRIVKEY_1, tx1.sighash(0, us.get(GENESIS_TXID, 0).script_pubkey))
    tx1.inputs[0].script_sig = [sig1, pubkey1]
    ok1, _ = us.validate_and_apply(tx1)
    assert ok1 is True

    # tx2: pubkey2 → pubkey1
    tx2 = Transaction(
        inputs=[TxInput(txid=tx1.txid, vout=0)],
        outputs=[TxOutput(80_000, _p2pkh_script_pubkey(pubkey1))],
    )
    _, sig2 = _ecdsa_sign(PRIVKEY_2, tx2.sighash(0, us.get(tx1.txid, 0).script_pubkey))
    tx2.inputs[0].script_sig = [sig2, pubkey2]
    ok2, msg2 = us.validate_and_apply(tx2)

    logging.info(f"tx2 Result: {ok2} — {msg2}")
    assert ok2 is True
    assert us.size == 1
    assert us.get(tx2.txid, 0).amount == 80_000
    logging.info("Transaction chain test passed!\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    test_utxoset_add_and_get()
    test_utxoset_remove()
    test_utxoset_coinbase()
    test_p2pkh_spend_valid()
    test_p2pkh_spend_wrong_sig()
    test_p2pkh_double_spend()
    test_intra_tx_double_spend()
    test_inflation_rejected()
    test_p2wpkh_spend_valid()
    test_p2wpkh_wrong_pubkey()
    test_p2wsh_2of2_spend_valid()
    test_p2wsh_missing_sig()
    test_multi_input_transaction()
    test_transaction_chain()
    print("\nAll UTXO tests passed!")
