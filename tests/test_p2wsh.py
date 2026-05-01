import logging
from ecdsa import SigningKey, SECP256k1

from src.engine import BitcoinScriptInterpreter
from src.script import Script
from src.crypto import sha256
from src.transactions import p2wsh


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


# ── Helper ────────────────────────────────────────────────────────────────

def _build_p2wsh_vm(
    m: int,
    pubkeys: list[bytes],
    sigs: list[bytes],
    tx_sig_hash: bytes,
) -> BitcoinScriptInterpreter:
    """Build a P2WSH multisig VM ready to execute."""
    n = len(pubkeys)
    pk_items             = " ".join(f"<{pk.hex()}>" for pk in pubkeys)
    witness_script_bytes = Script.parse(
        f"OP_{m} {pk_items} OP_{n} OP_CHECKMULTISIG"
    ).serialize()

    script_pubkey = Script.parse(f"OP_0 <{sha256(witness_script_bytes).hex()}>")
    witness_data  = [b""] + list(sigs) + [witness_script_bytes]

    return BitcoinScriptInterpreter(
        script=script_pubkey, witness=witness_data, tx_sig_hash=tx_sig_hash
    )


# ── P2WSH VM tests ────────────────────────────────────────────────────────

def test_p2wsh_1of2_valid():
    logging.info("=== P2WSH 1-of-2 Multisig (Valid) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    logging.info(f"pubkey1 : {pubkey1.hex()}")
    logging.info(f"sig1    : {sig1.hex()}")

    vm = _build_p2wsh_vm(1, [pubkey1, pubkey2], [sig1], DUMMY_MSG)
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is True, "P2WSH 1-of-2 should pass with one valid signature"
    logging.info("P2WSH 1-of-2 valid test passed!\n")


def test_p2wsh_2of2_valid():
    logging.info("=== P2WSH 2-of-2 Multisig (Valid) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2, sig2 = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)
    logging.info(f"pubkey1 : {pubkey1.hex()}")
    logging.info(f"pubkey2 : {pubkey2.hex()}")

    vm = _build_p2wsh_vm(2, [pubkey1, pubkey2], [sig1, sig2], DUMMY_MSG)
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is True, "P2WSH 2-of-2 should pass with both valid signatures"
    logging.info("P2WSH 2-of-2 valid test passed!\n")


def test_p2wsh_tampered_sig():
    logging.info("=== P2WSH Tampered Signature (Expected to Fail) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    bad_sig = bytes([sig1[0] ^ 0xFF]) + sig1[1:]
    logging.info(f"Tampered sig : {bad_sig.hex()}")

    vm = _build_p2wsh_vm(1, [pubkey1, pubkey2], [bad_sig], DUMMY_MSG)
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2WSH should fail with a tampered signature"
    logging.info("P2WSH tampered-sig test passed!\n")


def test_p2wsh_tampered_witness_script():
    logging.info("=== P2WSH Tampered Witness Script (Expected to Fail) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]

    # scriptPubKey commits to the correct witness script hash
    correct_bytes = Script.parse(
        f"OP_1 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    ).serialize()
    script_pubkey = Script.parse(f"OP_0 <{sha256(correct_bytes).hex()}>")

    # Attacker substitutes a trivially-true witness script
    malicious_bytes = Script.parse("OP_1").serialize()
    vm = BitcoinScriptInterpreter(
        script=script_pubkey,
        witness=[b"", sig1, malicious_bytes],
        tx_sig_hash=DUMMY_MSG,
    )
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2WSH should reject a substituted witness script"
    logging.info("P2WSH tampered-witness-script test passed!\n")


def test_p2wsh_wrong_sighash():
    logging.info("=== P2WSH Wrong Sighash (Expected to Fail) ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    wrong_msg = b"\x00" * 32
    logging.info(f"Sig committed to : {DUMMY_MSG.hex()}")
    logging.info(f"Verifying against: {wrong_msg.hex()}")

    vm = _build_p2wsh_vm(1, [pubkey1, pubkey2], [sig1], wrong_msg)
    is_valid = vm.execute()
    logging.info(f"Validation Result: {is_valid}")
    assert is_valid is False, "P2WSH should fail when sighash doesn't match"
    logging.info("P2WSH wrong-sighash test passed!\n")


# ── p2wsh() wrapper tests ─────────────────────────────────────────────────

def test_p2wsh_wrapper_1of2():
    logging.info("=== p2wsh() wrapper: 1-of-2 multisig ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    witness_script = Script.parse(
        f"OP_1 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    )
    result = p2wsh([b"", sig1], witness_script, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is True
    logging.info("p2wsh() wrapper 1-of-2 test passed!\n")


def test_p2wsh_wrapper_2of2():
    logging.info("=== p2wsh() wrapper: 2-of-2 multisig ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2, sig2 = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)
    witness_script = Script.parse(
        f"OP_2 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    )
    result = p2wsh([b"", sig1, sig2], witness_script, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is True
    logging.info("p2wsh() wrapper 2-of-2 test passed!\n")


def test_p2wsh_wrapper_wrong_sig():
    logging.info("=== p2wsh() wrapper: wrong sig should fail ===")

    pubkey1, sig1 = _ecdsa_sign(PRIVKEY_1, DUMMY_MSG)
    pubkey2        = _ecdsa_sign(PRIVKEY_2, DUMMY_MSG)[0]
    bad_sig = bytes([sig1[0] ^ 0xFF]) + sig1[1:]
    witness_script = Script.parse(
        f"OP_1 <{pubkey1.hex()}> <{pubkey2.hex()}> OP_2 OP_CHECKMULTISIG"
    )
    result = p2wsh([b"", bad_sig], witness_script, DUMMY_MSG)
    logging.info(f"Validation Result: {result}")
    assert result is False
    logging.info("p2wsh() wrapper wrong-sig test passed!\n")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    test_p2wsh_1of2_valid()
    test_p2wsh_2of2_valid()
    test_p2wsh_tampered_sig()
    test_p2wsh_tampered_witness_script()
    test_p2wsh_wrong_sighash()
    test_p2wsh_wrapper_1of2()
    test_p2wsh_wrapper_2of2()
    test_p2wsh_wrapper_wrong_sig()
    print("\nAll P2WSH tests passed!")
