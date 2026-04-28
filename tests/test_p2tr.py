import hashlib
import logging
import pytest
from ecdsa import SECP256k1
from ecdsa.ecdsa import generator_secp256k1

from src.engine import BitcoinScriptInterpreter
from src.script import Script
from src.crypto import verify_schnorr, aggregate_pubkeys
from src.transactions import p2tr


# ── BIP340 signing helper (test-only) ────────────────────────────────────

def _tagged_hash(tag: str, data: bytes) -> bytes:
    h = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(h + h + data).digest()


def _schnorr_sign(
    private_key_int: int,
    msg: bytes,
    aux_rand: bytes = b"\x00" * 32,
) -> tuple[bytes, bytes]:
    """Return (x_only_pubkey_32bytes, signature_64bytes) via BIP340."""
    n = SECP256k1.order
    G = generator_secp256k1

    d0 = private_key_int % n
    P = d0 * G
    d = d0 if P.y() % 2 == 0 else n - d0
    P_x = P.x().to_bytes(32, "big")

    t = d ^ int.from_bytes(_tagged_hash("BIP0340/aux", aux_rand), "big")
    rand = _tagged_hash("BIP0340/nonce", t.to_bytes(32, "big") + P_x + msg)
    k0 = int.from_bytes(rand, "big") % n
    assert k0 != 0

    R = k0 * G
    k = k0 if R.y() % 2 == 0 else n - k0
    R_x = R.x().to_bytes(32, "big")

    e = int.from_bytes(_tagged_hash("BIP0340/challenge", R_x + P_x + msg), "big") % n
    s = (k + e * d) % n

    return P_x, R_x + s.to_bytes(32, "big")


# ── Shared test data ──────────────────────────────────────────────────────

DUMMY_MSG = bytes.fromhex(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

PRIVKEY_1 = 1
PRIVKEY_2 = 2


# ── P2TR VM tests (mirror test_p2sh.py style) ────────────────────────────

def test_p2tr_valid_signature():
    logging.info("=== Running P2TR Key-Path Spend Test (Valid Signature) ===")

    pubkey, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    logging.info(f"x-only pubkey : {pubkey.hex()}")
    logging.info(f"Schnorr sig   : {sig.hex()}")

    # scriptPubKey: OP_1 <32-byte-x-only-pubkey>
    script_pubkey = Script([0x51, pubkey])

    # Witness stack for key-path spend: [sig]
    witness_data = [sig]

    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        witness=witness_data,
        tx_sig_hash=DUMMY_MSG,
    )

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is True, "P2TR should pass with a valid Schnorr signature"
    logging.info("P2TR valid-signature test passed!\n")


def test_p2tr_tampered_signature():
    logging.info("=== Running P2TR Test (Tampered Signature — Expected to Fail) ===")

    pubkey, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    logging.info(f"x-only pubkey : {pubkey.hex()}")
    logging.info(f"Tampered sig  : {bad_sig.hex()}")

    script_pubkey = Script([0x51, pubkey])

    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        witness=[bad_sig],
        tx_sig_hash=DUMMY_MSG,
    )

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2TR should fail with a tampered signature"
    logging.info("P2TR tampered-signature test passed!\n")


def test_p2tr_wrong_pubkey():
    logging.info("=== Running P2TR Test (Wrong Pubkey — Expected to Fail) ===")

    pubkey1, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2, _   = _schnorr_sign(PRIVKEY_2, DUMMY_MSG)
    logging.info("Signing with key-1, verifying against key-2's pubkey")

    script_pubkey = Script([0x51, pubkey2])

    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        witness=[sig],
        tx_sig_hash=DUMMY_MSG,
    )

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2TR should fail when pubkey doesn't match signer"
    logging.info("P2TR wrong-pubkey test passed!\n")


def test_p2tr_wrong_message():
    logging.info("=== Running P2TR Test (Wrong Sighash — Expected to Fail) ===")

    pubkey, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    wrong_msg = b"\x00" * 32
    logging.info(f"Signature committed to: {DUMMY_MSG.hex()}")
    logging.info(f"Verifying against:      {wrong_msg.hex()}")

    script_pubkey = Script([0x51, pubkey])

    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        witness=[sig],
        tx_sig_hash=wrong_msg,
    )

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2TR should fail when sighash doesn't match"
    logging.info("P2TR wrong-message test passed!\n")


# ── verify_schnorr() unit tests ───────────────────────────────────────────

def test_verify_schnorr_valid():
    pubkey, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    assert verify_schnorr(pubkey, sig, DUMMY_MSG) is True


def test_verify_schnorr_tampered_s():
    pubkey, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    bad_sig = sig[:-1] + bytes([sig[-1] ^ 0x01])
    assert verify_schnorr(pubkey, bad_sig, DUMMY_MSG) is False


def test_verify_schnorr_bad_pubkey_length():
    _, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    assert verify_schnorr(b"\x02" + b"\x00" * 32, sig, DUMMY_MSG) is False


def test_verify_schnorr_truncated_sig():
    pubkey, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    assert verify_schnorr(pubkey, sig[:32], DUMMY_MSG) is False


def test_verify_schnorr_empty_msg():
    pubkey, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    assert verify_schnorr(pubkey, sig, b"") is False


def test_verify_schnorr_sig_with_sighash_type():
    pubkey, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    assert verify_schnorr(pubkey, sig + b"\x00", DUMMY_MSG) is True


# ── BIP340 official test vector ───────────────────────────────────────────

def test_bip340_official_vector():
    logging.info("=== BIP340 Official Test Vector #0 (privkey=0x03) ===")
    pubkey = bytes.fromhex(
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    )
    msg = b"\x00" * 32
    sig = bytes.fromhex(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    )

    script_pubkey = Script([0x51, pubkey])

    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        witness=[sig],
        tx_sig_hash=msg,
    )

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is True
    logging.info("BIP340 official vector test passed!\n")


# ── Key aggregation helper (test-only) ───────────────────────────────────

def _aggregate_sign(private_keys: list[int], msg: bytes) -> tuple[bytes, bytes]:
    """
    MuSig-style key aggregation + signing (educational, single-round).

    Steps:
      1. Derive even-y adjusted private key and x-only pubkey for each signer.
      2. Call aggregate_pubkeys() to get the aggregate x-only pubkey.
      3. Compute aggregate private key: d_agg = Σ a_i * d_i  (mod n)
         using the same coefficients a_i = H("KeyAgg/coeff", L || P_i).
      4. Sign with d_agg via standard BIP340 — _schnorr_sign handles even-y.

    Returns (agg_pubkey_32bytes, schnorr_sig_64bytes).
    """
    n = SECP256k1.order
    G = generator_secp256k1

    # Step 1 — even-y adjusted keys and x-only pubkeys
    adj_privkeys: list[int] = []
    pub_bytes: list[bytes] = []
    for d0 in private_keys:
        d0 = d0 % n
        P = d0 * G
        d = d0 if P.y() % 2 == 0 else n - d0
        adj_privkeys.append(d)
        pub_bytes.append((d * G).x().to_bytes(32, "big"))

    # Step 2 — aggregate public key (delegates to crypto.py)
    agg_pubkey = aggregate_pubkeys(pub_bytes)

    # Step 3 — aggregate private key with the same coefficients
    L = _tagged_hash("KeyAgg/list", b"".join(pub_bytes))
    d_agg = 0
    for d, pk in zip(adj_privkeys, pub_bytes):
        a_i = int.from_bytes(_tagged_hash("KeyAgg/coeff", L + pk), "big") % n
        d_agg = (d_agg + a_i * d) % n

    # Step 4 — sign; _schnorr_sign re-applies even-y adjustment internally
    _, sig = _schnorr_sign(d_agg, msg)

    return agg_pubkey, sig


# ── Key aggregation tests ─────────────────────────────────────────────────

def test_key_aggregation_2of2():
    logging.info("=== P2TR Key Aggregation: 2-of-2 MuSig-style ===")

    agg_pubkey, sig = _aggregate_sign([PRIVKEY_1, PRIVKEY_2], DUMMY_MSG)
    logging.info(f"Aggregate pubkey : {agg_pubkey.hex()}")
    logging.info(f"Aggregate sig    : {sig.hex()}")

    # The aggregated key is indistinguishable from a single-signer P2TR key
    script_pubkey = Script([0x51, agg_pubkey])
    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        witness=[sig],
        tx_sig_hash=DUMMY_MSG,
    )
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is True, "2-of-2 aggregated key-path spend should succeed"
    logging.info("Key aggregation 2-of-2 test passed!\n")


def test_key_aggregation_wrong_sig():
    logging.info("=== P2TR Key Aggregation: wrong sig should fail ===")

    agg_pubkey, sig = _aggregate_sign([PRIVKEY_1, PRIVKEY_2], DUMMY_MSG)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]

    script_pubkey = Script([0x51, agg_pubkey])
    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        witness=[bad_sig],
        tx_sig_hash=DUMMY_MSG,
    )
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False
    logging.info("Key aggregation tampered-sig test passed!\n")


def test_key_aggregation_order_matters():
    logging.info("=== P2TR Key Aggregation: key order changes aggregate pubkey ===")

    agg_12, _ = _aggregate_sign([PRIVKEY_1, PRIVKEY_2], DUMMY_MSG)
    agg_21, _ = _aggregate_sign([PRIVKEY_2, PRIVKEY_1], DUMMY_MSG)

    # Different orderings → different aggregate keys (L depends on concatenation order)
    logging.info(f"Agg(key1, key2): {agg_12.hex()}")
    logging.info(f"Agg(key2, key1): {agg_21.hex()}")
    assert agg_12 != agg_21, "Key order should affect the aggregate pubkey"
    logging.info("Key order test passed!\n")


def test_aggregate_pubkeys_unit():
    """aggregate_pubkeys() returns a 32-byte x-only key and is deterministic."""
    pubkey1, _ = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2, _ = _schnorr_sign(PRIVKEY_2, DUMMY_MSG)

    agg = aggregate_pubkeys([pubkey1, pubkey2])
    assert len(agg) == 32
    # Deterministic
    assert aggregate_pubkeys([pubkey1, pubkey2]) == agg


# ── p2tr() wrapper tests (single-key and multi-key) ──────────────────────

def test_p2tr_wrapper_single_key():
    logging.info("=== p2tr() wrapper: single pubkey ===")
    pubkey, sig = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)
    result = p2tr(sig, [pubkey], DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is True


def test_p2tr_wrapper_multi_key():
    logging.info("=== p2tr() wrapper: multi-key aggregation (2-of-2) ===")
    _, sig    = _aggregate_sign([PRIVKEY_1, PRIVKEY_2], DUMMY_MSG)
    pubkey1   = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)[0]
    pubkey2   = _schnorr_sign(PRIVKEY_2, DUMMY_MSG)[0]

    result = p2tr(sig, [pubkey1, pubkey2], DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is True


def test_p2tr_wrapper_multi_key_wrong_sig():
    logging.info("=== p2tr() wrapper: multi-key, wrong sig should fail ===")
    _, sig  = _aggregate_sign([PRIVKEY_1, PRIVKEY_2], DUMMY_MSG)
    pubkey1 = _schnorr_sign(PRIVKEY_1, DUMMY_MSG)[0]
    pubkey2 = _schnorr_sign(PRIVKEY_2, DUMMY_MSG)[0]
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]

    result = p2tr(bad_sig, [pubkey1, pubkey2], DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    test_p2tr_valid_signature()
    test_p2tr_tampered_signature()
    test_p2tr_wrong_pubkey()
    test_p2tr_wrong_message()
    test_verify_schnorr_valid()
    test_verify_schnorr_tampered_s()
    test_verify_schnorr_bad_pubkey_length()
    test_verify_schnorr_truncated_sig()
    test_verify_schnorr_empty_msg()
    test_verify_schnorr_sig_with_sighash_type()
    test_bip340_official_vector()
    test_key_aggregation_2of2()
    test_key_aggregation_wrong_sig()
    test_key_aggregation_order_matters()
    test_aggregate_pubkeys_unit()
    print("\nAll P2TR / Schnorr tests passed!")
