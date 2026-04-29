from common import generate_asm_script
from crypto import generate_sig_pair, hash160, sha256
from script import Script


def generate_template(transaction_type: str, tx_hash: bytes) -> tuple[str, str, str]:
    """
    Enter transaction type & TX hash, return pair(scriptSig, scriptPubkey, witness)
    """
    match transaction_type.upper():
        case "P2PK":
            return generate_p2pk_template(tx_hash)
        case "P2PKH":
            return generate_p2pkh_template(tx_hash)
        case "P2SH":
            return generate_p2sh_template(tx_hash)
        case "P2WPKH":
            return generate_p2wpkh_template(tx_hash)
        case "P2WSH":
            return generate_p2wsh_template(tx_hash)
        case "P2TR":
            return generate_p2tr_template(tx_hash)
        case _:
            raise ValueError(f"Unknown transaction type: {transaction_type}")


def generate_p2pk_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk, sig = generate_sig_pair(tx_hash)

    scriptSig = generate_asm_script("<{}> # sig", sig)
    scriptPubkey = generate_asm_script("<{}> # pubkey\nOP_CHECKSIG", pk)

    return (scriptSig, scriptPubkey, "")


def generate_p2pkh_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk, sig = generate_sig_pair(tx_hash)
    pkh = hash160(pk)

    scriptSig = generate_asm_script("<{}> # sig\n<{}> # pubkey", sig, pk)
    scriptPubkey = generate_asm_script(
        "OP_DUP\nOP_HASH160\n<{}> # pubkey hash\nOP_EQUALVERIFY\nOP_CHECKSIG", pkh
    )

    return (scriptSig, scriptPubkey, "")


def generate_p2sh_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk1, sig1 = generate_sig_pair(tx_hash)
    pk2, sig2 = generate_sig_pair(tx_hash)
    redeem_script_asm = generate_asm_script(
        "OP_2 <{}> <{}> OP_2 OP_CHECKMULTISIG", pk1, pk2
    )
    redeem_script_bytes = Script.parse(redeem_script_asm).serialize()
    redeem_script_hash = hash160(redeem_script_bytes)

    scriptSig = generate_asm_script(
        "<{}>\n<{}> # sig1 sig2 ...\n{{{}}} # redeem script (pubkey1 pubkey2 ...)",
        sig1,
        sig2,
        redeem_script_asm,
    )
    scriptPubkey = generate_asm_script(
        "OP_HASH160\n<{}> # redeem script hash\nOP_EQUAL", redeem_script_hash
    )

    return (scriptSig, scriptPubkey, "")


def generate_p2wpkh_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk, sig = generate_sig_pair(tx_hash)
    pkh = hash160(pk)

    scriptPubkey = generate_asm_script("OP_0\n<{}> # pubkey hash", pkh)
    witness = generate_asm_script("<{}> # sig\n<{}> # pubkey", sig, pk)

    return ("", scriptPubkey, witness)


def generate_p2wsh_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk, sig = generate_sig_pair(tx_hash)
    witness_script_asm = generate_asm_script("<{}> # pubkey\nOP_CHECKSIG", pk)
    witness_script_bytes = Script.parse(witness_script_asm).serialize()
    witness_script_hash = sha256(witness_script_bytes)

    scriptPubkey = generate_asm_script(
        "OP_0\n<{}> # witness script hash", witness_script_hash
    )
    witness = generate_asm_script(
        "<{}> # sig\n{{{}}} # witness script", sig, witness_script_asm
    )

    return ("", scriptPubkey, witness)


def generate_p2tr_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk, sig = generate_sig_pair(tx_hash)
    witness_script_asm = generate_asm_script("<{}> # pubkey\nOP_CHECKSIG", pk)
    witness_script_bytes = Script.parse(witness_script_asm).serialize()
    witness_script_hash = sha256(witness_script_bytes)

    scriptPubkey = generate_asm_script(
        "OP_1\n<{}> # witness script hash", witness_script_hash
    )
    witness = generate_asm_script(
        "<{}> # sig\n{{{}}} # witness script", sig, witness_script_asm
    )

    return ("", scriptPubkey, witness)
