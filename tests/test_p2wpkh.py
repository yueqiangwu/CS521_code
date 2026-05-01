import logging
from ecdsa import SigningKey, SECP256k1

from src.engine import BitcoinScriptInterpreter
from src.script import Script
from src.crypto import hash160
from src.transactions import p2wpkh


# ── ECDSA signing helper ──────────────────────────────────────────────────

def _ecdsa_sign(private_key_int: int, msg: bytes) -> tuple[bytes, bytes]:
    """Return (pubkey_64bytes, sig_with_sighash) using sign_digest."""
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


# ── P2WPKH VM tests ───────────────────────────────────────────────────────

def test_p2wpkh_valid():
    logging.info("=== P2WPKH Valid Signature ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey_hash = hash160(pubkey)
    logging.info(f"pubkey      : {pubkey.hex()}")
    logging.info(f"pubkey_hash : {pubkey_hash.hex()}")
    logging.info(f"sig         : {sig.hex()}")

    # scriptPubKey: OP_0 <20-byte-hash>
    script_pubkey = Script.parse(f"OP_0 <{pubkey_hash.hex()}>")
    # witness: [sig, pubkey]
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=[sig, pubkey], tx_sig_hash=DUMMY_MSG
    )

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is True, "P2WPKH should pass with a valid signature"
    logging.info("P2WPKH valid test passed!\n")


def test_p2wpkh_tampered_sig():
    logging.info("=== P2WPKH Tampered Signature (Expected to Fail) ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey_hash = hash160(pubkey)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    logging.info(f"Tampered sig: {bad_sig.hex()}")

    script_pubkey = Script.parse(f"OP_0 <{pubkey_hash.hex()}>")
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=[bad_sig, pubkey], tx_sig_hash=DUMMY_MSG
    )

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2WPKH should fail with a tampered signature"
    logging.info("P2WPKH tampered-sig test passed!\n")


def test_p2wpkh_wrong_pubkey():
    logging.info("=== P2WPKH Wrong Pubkey (Expected to Fail via hash mismatch) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    # scriptPubKey commits to pubkey1's hash, witness provides pubkey2
    pubkey1_hash = hash160(pubkey1)
    logging.info("scriptPubKey uses hash160(pubkey1), witness has pubkey2")

    script_pubkey = Script.parse(f"OP_0 <{pubkey1_hash.hex()}>")
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=[sig1, pubkey2], tx_sig_hash=DUMMY_MSG
    )

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2WPKH should fail when witness pubkey doesn't match hash"
    logging.info("P2WPKH wrong-pubkey test passed!\n")


def test_p2wpkh_wrong_sighash():
    logging.info("=== P2WPKH Wrong Sighash (Expected to Fail) ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey_hash = hash160(pubkey)
    wrong_msg   = b"\x00" * 32
    logging.info(f"Sig committed to : {DUMMY_MSG.hex()}")
    logging.info(f"Verifying against: {wrong_msg.hex()}")

    script_pubkey = Script.parse(f"OP_0 <{pubkey_hash.hex()}>")
    vm = BitcoinScriptInterpreter(
        script=script_pubkey, witness=[sig, pubkey], tx_sig_hash=wrong_msg
    )

    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2WPKH should fail when sighash doesn't match"
    logging.info("P2WPKH wrong-sighash test passed!\n")


# ── p2wpkh() wrapper tests ────────────────────────────────────────────────

def test_p2wpkh_wrapper_valid():
    logging.info("=== p2wpkh() wrapper: valid ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    result = p2wpkh(sig, pubkey, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is True
    logging.info("p2wpkh() wrapper valid test passed!\n")


def test_p2wpkh_wrapper_tampered_sig():
    logging.info("=== p2wpkh() wrapper: tampered sig should fail ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    result = p2wpkh(bad_sig, pubkey, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is False
    logging.info("p2wpkh() wrapper tampered-sig test passed!\n")


def test_p2wpkh_wrapper_wrong_sighash():
    logging.info("=== p2wpkh() wrapper: wrong sighash should fail ===")

    pubkey, sig = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    result = p2wpkh(sig, pubkey, b"\x00" * 32)
    logging.info(f"Validation Result: {result}")
    assert result is False
    logging.info("p2wpkh() wrapper wrong-sighash test passed!\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    test_p2wpkh_valid()
    test_p2wpkh_tampered_sig()
    test_p2wpkh_wrong_pubkey()
    test_p2wpkh_wrong_sighash()
    test_p2wpkh_wrapper_valid()
    test_p2wpkh_wrapper_tampered_sig()
    test_p2wpkh_wrapper_wrong_sighash()
    print("\nAll P2WPKH tests passed!")
