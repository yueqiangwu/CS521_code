import logging
from ecdsa import SigningKey, SECP256k1

from src.engine import BitcoinScriptInterpreter
from src.script import Script
from src.crypto import hash160
from src.common import generate_p2pkh_script
from src.transactions import p2pkh


# ── ECDSA signing helper ──────────────────────────────────────────────────

def _ecdsa_sign(private_key_int: int, msg: bytes) -> tuple[bytes, bytes]:
    """Return (pubkey_64bytes, sig_with_sighash) using sign_digest (no internal hashing)."""
    sk = SigningKey.from_string(private_key_int.to_bytes(32, "big"), curve=SECP256k1)
    pubkey = sk.get_verifying_key().to_string()
    sig    = sk.sign_digest(msg) + b"\x01"
    return pubkey, sig


# ── Shared test data ──────────────────────────────────────────────────────

DUMMY_MSG = bytes.fromhex(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

PRIVKEY_1 = 1
PRIVKEY_2 = 2


# ── P2PKH VM tests ────────────────────────────────────────────────────────

def test_p2pkh_valid():
    logging.info("=== P2PKH Valid Signature ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey_hash = hash160(pubkey)
    logging.info(f"pubkey      : {pubkey.hex()}")
    logging.info(f"pubkey_hash : {pubkey_hash.hex()}")
    logging.info(f"sig         : {sig.hex()}")

    # Full combined script: <sig> <pubkey> OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    script = Script.parse(generate_p2pkh_script(sig, pubkey, pubkey_hash))
    vm = BitcoinScriptInterpreter(script=script, tx_sig_hash=DUMMY_MSG)

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is True, "P2PKH should pass with a valid signature"
    logging.info("P2PKH valid test passed!\n")


def test_p2pkh_tampered_sig():
    logging.info("=== P2PKH Tampered Signature (Expected to Fail) ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey_hash = hash160(pubkey)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    logging.info(f"Tampered sig: {bad_sig.hex()}")

    script = Script.parse(generate_p2pkh_script(bad_sig, pubkey, pubkey_hash))
    vm = BitcoinScriptInterpreter(script=script, tx_sig_hash=DUMMY_MSG)

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2PKH should fail with a tampered signature"
    logging.info("P2PKH tampered-sig test passed!\n")


def test_p2pkh_wrong_pubkey():
    logging.info("=== P2PKH Wrong Pubkey (Expected to Fail via OP_EQUALVERIFY) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    pubkey1_hash   = hash160(pubkey1)
    logging.info("Script commits to pubkey1 hash, but unlocking uses pubkey2")

    # Script locks to pubkey1's hash but the unlocking pushes pubkey2
    # → OP_EQUALVERIFY: hash160(pubkey2) != pubkey1_hash → fail
    script = Script.parse(generate_p2pkh_script(sig1, pubkey2, pubkey1_hash))
    vm = BitcoinScriptInterpreter(script=script, tx_sig_hash=DUMMY_MSG)

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2PKH should fail when pubkey doesn't match hash"
    logging.info("P2PKH wrong-pubkey test passed!\n")


def test_p2pkh_wrong_sighash():
    logging.info("=== P2PKH Wrong Sighash (Expected to Fail) ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey_hash  = hash160(pubkey)
    wrong_msg    = b"\x00" * 32
    logging.info(f"Sig committed to : {DUMMY_MSG.hex()}")
    logging.info(f"Verifying against: {wrong_msg.hex()}")

    script = Script.parse(generate_p2pkh_script(sig, pubkey, pubkey_hash))
    vm = BitcoinScriptInterpreter(script=script, tx_sig_hash=wrong_msg)

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2PKH should fail when sighash doesn't match"
    logging.info("P2PKH wrong-sighash test passed!\n")


# ── p2pkh() wrapper tests ─────────────────────────────────────────────────

def test_p2pkh_wrapper_valid():
    logging.info("=== p2pkh() wrapper: valid ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    result = p2pkh(sig, pubkey, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is True
    logging.info("p2pkh() wrapper valid test passed!\n")


def test_p2pkh_wrapper_tampered_sig():
    logging.info("=== p2pkh() wrapper: tampered sig should fail ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    result = p2pkh(bad_sig, pubkey, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is False
    logging.info("p2pkh() wrapper tampered-sig test passed!\n")


def test_p2pkh_wrapper_wrong_sighash():
    logging.info("=== p2pkh() wrapper: wrong sighash should fail ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    result = p2pkh(sig, pubkey, b"\x00" * 32)
    logging.info(f"Validation Result: {result}")
    assert result is False
    logging.info("p2pkh() wrapper wrong-sighash test passed!\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    test_p2pkh_valid()
    test_p2pkh_tampered_sig()
    test_p2pkh_wrong_pubkey()
    test_p2pkh_wrong_sighash()
    test_p2pkh_wrapper_valid()
    test_p2pkh_wrapper_tampered_sig()
    test_p2pkh_wrapper_wrong_sighash()
    print("\nAll P2PKH tests passed!")
