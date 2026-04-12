import hashlib

from ecdsa import VerifyingKey, SECP256k1


def hash160(data: bytes) -> bytes:
    sha2 = hashlib.sha256(data).digest()
    h = hashlib.new("ripemd160")
    h.update(sha2)
    return h.digest()


def verify_sig(pubkey: bytes, sig: bytes, msg_hash: bytes) -> bool:
    try:
        vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
        return vk.verify(sig[:-1], msg_hash)
    except:
        return False
