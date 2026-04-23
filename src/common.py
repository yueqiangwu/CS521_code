VM_TRUE = b"\x01"
VM_FALSE = b"\x00"


class VMError(RuntimeError):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return f"Transaction failed: {self.message}"


def generate_asm_script(templete: str, *items: bytes) -> str:
    return templete.format(*(item.hex() for item in items))


def generate_p2pkh_script(sig: bytes, pubkey: bytes, pubkey_hash: bytes) -> str:
    return generate_asm_script(
        "<{}> <{}> OP_DUP OP_HASH160 <{}> OP_EQUALVERIFY OP_CHECKSIG",
        sig,
        pubkey,
        pubkey_hash,
    )


def generate_segwit_p2pkh_script(pubkey_hash: bytes) -> str:
    return generate_asm_script("OP_0 <{}>", pubkey_hash)
