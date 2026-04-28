VM_TRUE = b"\x01"
VM_FALSE = b"\x00"


TX_HASH_SIZE = 32


class VMError(Exception):
    def __init__(self, message, status_code=400, payload=None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv["message"] = self.message
        rv["status"] = "error"
        return rv


def generate_asm_script(templete: str, *items: bytes) -> str:
    return templete.format(
        *(item.hex() if isinstance(item, bytes) else item for item in items)
    )


def generate_p2pkh_script(sig: bytes, pubkey: bytes, pubkey_hash: bytes) -> str:
    return generate_asm_script(
        "<{}> <{}> OP_DUP OP_HASH160 <{}> OP_EQUALVERIFY OP_CHECKSIG",
        sig,
        pubkey,
        pubkey_hash,
    )


def generate_segwit_p2pkh_script(pubkey_hash: bytes) -> str:
    return generate_asm_script("OP_0 <{}>", pubkey_hash)
