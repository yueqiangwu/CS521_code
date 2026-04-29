import hashlib
from ecdsa import VerifyingKey, SECP256k1, SigningKey
from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
from ecdsa.ellipticcurve import INFINITY, PointJacobi


def hash160(data: bytes) -> bytes:
    sha2 = hashlib.sha256(data).digest()
    h = hashlib.new("ripemd160")
    h.update(sha2)
    return h.digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generate_sig_pair(tx_hash: bytes) -> tuple[bytes, bytes]:
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()

    public_key = vk.to_string("compressed")
    signature = sk.sign_digest(tx_hash)
    signature_with_hashtype = signature + b"\x01"
    return public_key, signature_with_hashtype


def verify_sig(pubkey: bytes, sig: bytes, msg_hash: bytes) -> bool:
    try:
        vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
        return vk.verify_digest(sig[:-1], msg_hash)
    except:
        return False


def verify_multisig(pubkeys: list[bytes], sigs: list[bytes], sighash: bytes) -> bool:
    sig_idx = 0
    pub_idx = 0
    while sig_idx < len(sigs) and pub_idx < len(pubkeys):
        if verify_sig(pubkeys[pub_idx], sigs[sig_idx], sighash):
            sig_idx += 1
        pub_idx += 1
    return sig_idx == len(sigs)


# --- BIP340 Schnorr signature verification ---


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)"""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _lift_x(x: int):
    """Return secp256k1 point with the given x-coordinate and even y (BIP340)."""
    p = SECP256k1.curve.p()
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y % 2 == 0 else p - y)


def aggregate_pubkeys(pubkeys: list[bytes]) -> bytes:
    """
    MuSig-style Schnorr key aggregation (educational, not full BIP-327).

    Each signer's x-only pubkey is weighted by a coefficient
        a_i = H("KeyAgg/coeff", L || P_i)
    where L = H("KeyAgg/list", P_1 || ... || P_n).
    This prevents rogue-key attacks without an interactive proof-of-possession.

    Returns the 32-byte x-only aggregate public key.
    """
    if not pubkeys:
        raise ValueError("Need at least one public key")

    n = SECP256k1.order

    # Commitment to the full key list
    L = _tagged_hash("KeyAgg/list", b"".join(pubkeys))

    P_agg = INFINITY
    for pk_bytes in pubkeys:
        coords = _lift_x(int.from_bytes(pk_bytes, "big"))
        if coords is None:
            raise ValueError(f"Invalid pubkey: {pk_bytes.hex()}")
        a_i = int.from_bytes(_tagged_hash("KeyAgg/coeff", L + pk_bytes), "big") % n
        P_i = PointJacobi(curve_secp256k1, coords[0], coords[1], 1, n)
        P_agg = P_agg + a_i * P_i

    if P_agg == INFINITY:
        raise ValueError("Aggregate public key is the point at infinity")

    return P_agg.x().to_bytes(32, "big")


def verify_schnorr(pubkey: bytes, sig: bytes, msg: bytes) -> bool:
    """
    BIP340 Schnorr signature verification.

    pubkey : 32-byte x-only public key
    sig    : 64-byte raw Schnorr signature (r || s), or 65 bytes with sighash type appended
    msg    : 32-byte message (transaction sighash)
    """
    try:
        if len(pubkey) != 32 or not msg:
            return False

        raw_sig = sig[:-1] if len(sig) == 65 else sig
        if len(raw_sig) != 64:
            return False

        p = SECP256k1.curve.p()
        n = SECP256k1.order
        G = generator_secp256k1

        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:64], "big")

        if r >= p or s >= n:
            return False

        P_x = int.from_bytes(pubkey, "big")
        coords = _lift_x(P_x)
        if coords is None:
            return False

        P_point = PointJacobi(curve_secp256k1, coords[0], coords[1], 1, n)

        e = (
            int.from_bytes(
                _tagged_hash("BIP0340/challenge", raw_sig[:32] + pubkey + msg), "big"
            )
            % n
        )

        # R = s*G - e*P  ≡  s*G + (n-e)*P
        R = s * G + ((n - e) % n) * P_point

        if R == INFINITY:
            return False

        Rx, Ry = R.x(), R.y()
        return Ry % 2 == 0 and Rx == r

    except Exception:
        return False
