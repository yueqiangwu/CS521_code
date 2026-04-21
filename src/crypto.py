import hashlib
import logging
from ecdsa import VerifyingKey, SECP256k1


def hash160(data: bytes) -> bytes:
    sha2 = hashlib.sha256(data).digest()
    h = hashlib.new("ripemd160")
    h.update(sha2)
    return h.digest()

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()   

def verify_sig(pubkey: bytes, sig: bytes, msg_hash: bytes) -> bool:
    try:
        vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
        return vk.verify(sig[:-1], msg_hash)
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
