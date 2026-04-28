import logging
from ecdsa import SigningKey, SECP256k1

from src.engine import BitcoinScriptInterpreter
from src.script import Script
from src.crypto import hash160
from src.transactions import p2sh


# ── ECDSA signing helper (test-only) ─────────────────────────────────────

def _ecdsa_sign(private_key_int: int, msg: bytes) -> tuple[bytes, bytes]:
    """Return (pubkey_64bytes, sig_with_sighash_byte) using ECDSA/SECP256k1."""
    sk = SigningKey.from_string(private_key_int.to_bytes(32, "big"), curve=SECP256k1)
    pubkey = sk.get_verifying_key().to_string()  # 64-byte uncompressed (no prefix)
    sig    = sk.sign_digest(msg) + b"\x01"        # sign the raw digest; matches verify_digest in verify_sig
    return pubkey, sig


# ── Shared test data ──────────────────────────────────────────────────────

DUMMY_MSG = bytes.fromhex(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

PRIVKEY_1 = 1
PRIVKEY_2 = 2


# ── Helpers ───────────────────────────────────────────────────────────────

def _build_multisig_vm(
    m: int,
    pubkeys: list[bytes],
    sigs: list[bytes],
    tx_sig_hash: bytes,
) -> BitcoinScriptInterpreter:
    """Build a P2SH multisig VM ready to execute."""
    n = len(pubkeys)
    pk_items  = " ".join(f"<{pk.hex()}>" for pk in pubkeys)
    redeem_asm = f"OP_{m} {pk_items} OP_{n} OP_CHECKMULTISIG"
    redeem_script       = Script.parse(redeem_asm)
    redeem_script_bytes = redeem_script.serialize()

    script_hash = hash160(redeem_script_bytes)
    script_pubkey = Script.parse(f"OP_HASH160 <{script_hash.hex()}> OP_EQUAL")

    # initial_stack: dummy (OP_CHECKMULTISIG off-by-one bug) + sigs + redeem script
    initial_stack = [b""] + list(sigs) + [redeem_script_bytes]

    return BitcoinScriptInterpreter(
        script=script_pubkey,
        initial_stack=initial_stack,
        tx_sig_hash=tx_sig_hash,
    )


# ── P2SH VM tests ─────────────────────────────────────────────────────────

def test_p2sh_1of2_valid():
    logging.info("=== P2SH 1-of-2 Multisig (Valid) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    logging.info(f"pubkey1 : {pubkey1.hex()}")
    logging.info(f"sig1    : {sig1.hex()}")

    vm = _build_multisig_vm(1, [pubkey1, pubkey2], [sig1], DUMMY_MSG)
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is True, "P2SH 1-of-2 should pass with one valid signature"
    logging.info("P2SH 1-of-2 valid test passed!\n")


def test_p2sh_2of2_valid():
    logging.info("=== P2SH 2-of-2 Multisig (Valid) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2, sig2 = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)
    logging.info(f"pubkey1 : {pubkey1.hex()}")
    logging.info(f"pubkey2 : {pubkey2.hex()}")

    vm = _build_multisig_vm(2, [pubkey1, pubkey2], [sig1, sig2], DUMMY_MSG)
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is True, "P2SH 2-of-2 should pass with both valid signatures"
    logging.info("P2SH 2-of-2 valid test passed!\n")


def test_p2sh_tampered_sig():
    logging.info("=== P2SH Tampered Signature (Expected to Fail) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    bad_sig = bytes([sig1[0] ^ 0xFF]) + sig1[1:]
    logging.info(f"Tampered sig : {bad_sig.hex()}")

    vm = _build_multisig_vm(1, [pubkey1, pubkey2], [bad_sig], DUMMY_MSG)
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2SH should fail with a tampered signature"
    logging.info("P2SH tampered-sig test passed!\n")


def test_p2sh_wrong_sighash():
    logging.info("=== P2SH Wrong Sighash (Expected to Fail) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    wrong_msg = b"\x00" * 32
    logging.info(f"Sig committed to : {DUMMY_MSG.hex()}")
    logging.info(f"Verifying against: {wrong_msg.hex()}")

    vm = _build_multisig_vm(1, [pubkey1, pubkey2], [sig1], wrong_msg)
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2SH should fail when sighash doesn't match"
    logging.info("P2SH wrong-sighash test passed!\n")


def test_p2sh_tampered_redeem_script():
    logging.info("=== P2SH Tampered Redeem Script (Expected to Fail) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]

    # scriptPubKey commits to the correct redeem script
    correct_asm   = f"OP_1 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    correct_bytes = Script.parse(correct_asm).serialize()
    script_hash   = hash160(correct_bytes)
    script_pubkey = Script.parse(f"OP_HASH160 <{script_hash.hex()}> OP_EQUAL")

    # Attacker substitutes a trivially-true script
    malicious_bytes = Script.parse("OP_1").serialize()
    initial_stack   = [b"", sig1, malicious_bytes]

    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        initial_stack=initial_stack,
        tx_sig_hash=DUMMY_MSG,
    )
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2SH should reject a substituted redeem script"
    logging.info("P2SH tampered-redeem-script test passed!\n")


# ── p2sh() wrapper tests ──────────────────────────────────────────────────

def test_p2sh_wrapper_1of2():
    logging.info("=== p2sh() wrapper: 1-of-2 multisig ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]

    redeem_script = Script.parse(
        f"OP_1 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    )
    result = p2sh([b"", sig1], redeem_script, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is True
    logging.info("p2sh() wrapper 1-of-2 test passed!\n")


def test_p2sh_wrapper_2of2():
    logging.info("=== p2sh() wrapper: 2-of-2 multisig ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2, sig2 = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)

    redeem_script = Script.parse(
        f"OP_2 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    )
    result = p2sh([b"", sig1, sig2], redeem_script, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is True
    logging.info("p2sh() wrapper 2-of-2 test passed!\n")


def test_p2sh_wrapper_wrong_sig():
    logging.info("=== p2sh() wrapper: wrong sig should fail ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    bad_sig = bytes([sig1[0] ^ 0xFF]) + sig1[1:]

    redeem_script = Script.parse(
        f"OP_1 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    )
    result = p2sh([b"", bad_sig], redeem_script, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is False
    logging.info("p2sh() wrapper wrong-sig test passed!\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    test_p2sh_1of2_valid()
    test_p2sh_2of2_valid()
    test_p2sh_tampered_sig()
    test_p2sh_wrong_sighash()
    test_p2sh_tampered_redeem_script()
    test_p2sh_wrapper_1of2()
    test_p2sh_wrapper_2of2()
    test_p2sh_wrapper_wrong_sig()
    print("\nAll P2SH tests passed!")
