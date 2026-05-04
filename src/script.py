import re

from common import VMError, DisabledOpError, generate_asm_script
from crypto import generate_sig_pair, hash160, sha256
from opcodes import op_2_opcode, opcode_2_op, int_to_scriptnum


class Script:
    """
    Store instruction sequence
    """

    def __init__(self, cmds: list[bytes | int] | None = None):
        self.cmds = cmds or []

    def __repr__(self):
        return "\n".join(
            opcode_2_op(cmd) if isinstance(cmd, int) else cmd.hex() for cmd in self.cmds
        )

    @classmethod
    def parse(cls, raw_input: str, is_hex: bool = False):
        """
        Parse the input HEX/ASM string into a list of instructions
        """
        return cls.parse_hex(raw_input) if is_hex else cls.parse_asm(raw_input)

    @classmethod
    def parse_asm(cls, raw_input: str):
        hex_bytes = cls._asm_to_hex_bytes(raw_input)
        cmds = cls._hex_bytes_to_cmds(hex_bytes)
        return cls(cmds)

    @classmethod
    def parse_hex(cls, raw_input: str):
        try:
            hex_bytes = bytes.fromhex(raw_input)
        except Exception:
            raise VMError(f"Invalid hex string: {raw_input}")

        cmds = cls._hex_bytes_to_cmds(hex_bytes)
        return cls(cmds)

    def serialize(self) -> bytes:
        result = b""
        for cmd in self.cmds:
            if isinstance(cmd, int):
                result += bytes([cmd])
            elif isinstance(cmd, bytes):
                result += self._encode_pushdata_prefix(len(cmd))
                result += cmd
        return result

    @staticmethod
    def _encode_pushdata_prefix(length: int) -> bytes:
        if length < 0x4C:
            return bytes([length])
        elif length <= 0xFF:
            return bytes([0x4C, length])
        elif length <= 0xFFFF:
            return bytes([0x4D]) + length.to_bytes(2, "little")
        else:
            return bytes([0x4E]) + length.to_bytes(4, "little")

    @staticmethod
    def _asm_to_hex_bytes(raw_input: str) -> bytes:
        # remove description: //...
        lines = raw_input.split("\n")
        cleaned_content = " ".join(line.split("//")[0].strip() for line in lines)
        # parse all tokens
        pattern = r"#.*?#|\{.*?\}|<.*?>|\[.*?\]|\".*?\"|'.*?'|OP_\w+|\S+"
        tokens = re.findall(pattern, cleaned_content)

        result = b""
        i = 0

        while i < len(tokens):
            token = tokens[i]
            i += 1

            # Handling complier commands: #...#
            if token.startswith("#") and token.endswith("#"):
                raise DisabledOpError("Complier command not supported")
            # Handling nested ASM blocks: {...}
            if token.startswith("{") and token.endswith("}"):
                data = Script._asm_to_hex_bytes(token[1:-1])
                result += Script._encode_pushdata_prefix(len(data))
                result += data
                continue
            # Handling hex data: [...]/<...>
            if (token.startswith("[") and token.endswith("]")) or (
                token.startswith("<") and token.endswith(">")
            ):
                try:
                    data = bytes.fromhex(token[1:-1])
                except Exception:
                    raise VMError(f"Invalid hex data: {token}")
                result += Script._encode_pushdata_prefix(len(data))
                result += data
                continue
            # Handling string: "..."/'...'
            if (token.startswith('"') and token.endswith('"')) or (
                token.startswith("'") and token.endswith("'")
            ):
                try:
                    data = token[1:-1].encode()
                except Exception:
                    raise VMError(f"Invalid string: {token}")
                result += Script._encode_pushdata_prefix(len(data))
                result += data
                continue
            # Handling opcode: (OP_)...
            if (opcode := op_2_opcode(token)) is not None:
                result += bytes([opcode])
                continue
            # Handling pushdata: 0x01~0x4B + 0x...
            if token.startswith("0x") or token.startswith("0X"):
                hex_body = token[2:]
                if len(hex_body) % 2 == 1:
                    hex_body = "0" + hex_body
                try:
                    data = bytes.fromhex(hex_body)
                except Exception:
                    raise VMError(f"Invalid hex data: {token}")
                result += data
                continue
            # Handling number
            try:
                data = int_to_scriptnum(int(token))
                result += Script._encode_pushdata_prefix(len(data))
                result += data
                continue
            except Exception:
                pass

            raise VMError(f"Invalid token in ASM: {token}")

        return result

    @staticmethod
    def _hex_bytes_to_cmds(hex_bytes: bytes) -> list[bytes | int]:
        length = len(hex_bytes)
        i = 0
        cmds = []

        while i < length:
            current = hex_bytes[i]
            i += 1

            # push data (0x01 ~ 0x4b)
            if 0x01 <= current <= 0x4B:
                n = current
                if i + n > length:
                    raise VMError("Out of range")

                data = hex_bytes[i : i + n]
                i += n
                cmds.append(data)
            # OP_PUSHDATA1 (0x4c)
            elif current == 0x4C:
                if i > length:
                    raise VMError("Missing length byte")
                n = hex_bytes[i]
                i += 1
                if i + n > length:
                    raise VMError("Out of range")

                data = hex_bytes[i : i + n]
                i += n
                cmds.append(data)
            # OP_PUSHDATA2 (0x4d)
            elif current == 0x4D:
                if i + 1 >= length:
                    raise VMError("Missing length byte")
                n = int.from_bytes(hex_bytes[i : i + 2], "little")
                i += 2
                if i + n > length:
                    raise VMError("Out of range")

                data = hex_bytes[i : i + n]
                i += n
                cmds.append(data)
            # OP_PUSHDATA4 (0x4e)
            elif current == 0x4E:
                if i + 3 >= length:
                    raise VMError("Missing length byte")
                n = int.from_bytes(hex_bytes[i : i + 4], "little")
                i += 4
                if i + n > length:
                    raise VMError("Out of range")

                data = hex_bytes[i : i + n]
                i += n
                cmds.append(data)
            # other opcodes
            else:
                cmds.append(current)

        return cmds


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
        case _:
            raise ValueError(f"Unknown transaction type: {transaction_type}")


def generate_p2pk_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk, sig = generate_sig_pair(tx_hash)

    scriptSig = generate_asm_script("[{}] // sig", sig)
    scriptPubkey = generate_asm_script("[{}] // pubkey\nOP_CHECKSIG", pk)

    return (scriptSig, scriptPubkey, "")


def generate_p2pkh_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk, sig = generate_sig_pair(tx_hash)
    pkh = hash160(pk)

    scriptSig = generate_asm_script("[{}] // sig\n[{}] // pubkey", sig, pk)
    scriptPubkey = generate_asm_script(
        "OP_DUP\nOP_HASH160\n[{}] // pubkey hash\nOP_EQUALVERIFY\nOP_CHECKSIG", pkh
    )

    return (scriptSig, scriptPubkey, "")


def generate_p2sh_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk1, sig1 = generate_sig_pair(tx_hash)
    pk2, sig2 = generate_sig_pair(tx_hash)
    redeem_script_asm = generate_asm_script(
        "OP_2 //sig num\n// pubkey1 pubkey2 ...\n[{}]\n[{}]\nOP_2 //pubkey num\nOP_CHECKMULTISIG",
        pk1,
        pk2,
    )
    redeem_script_bytes = Script._asm_to_hex_bytes(redeem_script_asm)
    redeem_script_hash = hash160(redeem_script_bytes)

    scriptSig = generate_asm_script(
        "OP_0 // dummy\n// sig1 sig2 ...\n[{}]\n[{}]\n// redeem script hex\n{{\n{}\n}}",
        sig1,
        sig2,
        redeem_script_asm,
    )
    scriptPubkey = generate_asm_script(
        "OP_HASH160\n[{}] // redeem script hash\nOP_EQUAL", redeem_script_hash
    )

    return (scriptSig, scriptPubkey, "")


def generate_p2wpkh_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk, sig = generate_sig_pair(tx_hash)
    pkh = hash160(pk)

    scriptPubkey = generate_asm_script("OP_0\n[{}] // pubkey hash", pkh)
    witness = generate_asm_script("[{}] // sig\n[{}] // pubkey", sig, pk)

    return ("", scriptPubkey, witness)


def generate_p2wsh_template(tx_hash: bytes) -> tuple[str, str, str]:
    pk, sig = generate_sig_pair(tx_hash)
    witness_script_asm = generate_asm_script("[{}] // pubkey\nOP_CHECKSIG", pk)
    witness_script_bytes = Script._asm_to_hex_bytes(witness_script_asm)
    witness_script_hash = sha256(witness_script_bytes)

    scriptPubkey = generate_asm_script(
        "OP_0\n[{}] // witness script hash", witness_script_hash
    )
    witness = generate_asm_script(
        "[{}] // sig\n// witness script\n{{\n{}\n}}", sig, witness_script_asm
    )

    return ("", scriptPubkey, witness)
