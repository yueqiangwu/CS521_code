import re

from common import VMError, generate_asm_script
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
        # remove notes
        lines = raw_input.split("\n")
        cleaned_content = " ".join(line.split("#")[0].strip() for line in lines)

        # Valid token:
        # opcodes: (OP_)xxx
        # pushdata: <hex> / 0x01~0x4B + hex
        # hex script: {script}
        # number: 10 base
        # string: "str" / 'str'
        pattern = r"\{.*?\}|<.*?>|\".*?\"|'.*?'|OP_\w+|\S+"
        tokens = re.findall(pattern, cleaned_content)

        cmds = []
        i = 0

        while i < len(tokens):
            token = tokens[i]

            # Handling nested ASM blocks
            if token.startswith("{") and token.endswith("}"):
                inner_asm = token[1:-1]
                inner_script = cls.parse_asm(inner_asm)
                cmds.append(inner_script.serialize())
                i += 1
                continue

            # Handling hex data (<hex>)
            if token.startswith("<") and token.endswith(">"):
                try:
                    cmds.append(bytes.fromhex(token[1:-1]))
                except Exception:
                    raise VMError(f"Invalid hex data: {token}")
                i += 1
                continue

            # Handling string
            if (token.startswith('"') and token.endswith('"')) or (
                token.startswith("'") and token.endswith("'")
            ):
                try:
                    cmds.append(token[1:-1].encode())
                except Exception:
                    raise VMError(f"Invalid string data: {token}")
                i += 1
                continue

            # Handling opcode
            opcode = op_2_opcode(token)
            if opcode is not None:
                cmds.append(opcode)
                i += 1
                continue

            # Handling hex data (0x01~0x4B + hex) / hex opcode
            if token.startswith("0x") or token.startswith("0X"):
                try:
                    length = int(token, 16)
                except Exception:
                    raise VMError(f"Invalid hex number: {token}")
                if not (0x01 <= length <= 0x4B):
                    if opcode_2_op(length) is None:
                        cmds.append(int_to_scriptnum(length))
                    else:
                        cmds.append(length)
                    i += 1
                    continue

                data_bytes = b""
                cnt = 0
                is_valid = True

                while len(data_bytes) < length:
                    cnt += 1
                    if i + cnt == len(tokens):
                        is_valid = False
                        break

                    next_token = tokens[i + cnt]
                    if not (next_token.startswith("0x") or next_token.startswith("0X")):
                        if length == 1 and next_token == "1":
                            next_token = "0x51"
                        else:
                            raise VMError(f"Invalid pushdata content: {next_token}")

                    try:
                        data_bytes += bytes.fromhex(next_token[2:])
                    except Exception:
                        raise VMError(f"Invalid hex number: {next_token}")

                    if len(data_bytes) > length:
                        raise VMError(f"Invalid pushdata content length: {next_token}")

                if is_valid:
                    cmds.append(data_bytes)
                    i += cnt + 1
                else:
                    cmds.append(int_to_scriptnum(length))
                    i += 1
                continue

            # Handling others
            try:
                value = int(token)
                cmds.append(int_to_scriptnum(value))
            except Exception:
                raise VMError(f"Invalid token in ASM: {token}")
            i += 1

        return cls(cmds)

    @classmethod
    def parse_hex(cls, raw_input: str):
        try:
            raw = bytes.fromhex(raw_input)
        except Exception:
            raise VMError("Invalid hex string")

        length = len(raw)
        i = 0
        cmds = []

        while i < length:
            current = raw[i]
            i += 1

            # push data (0x01 ~ 0x4b)
            if 0x01 <= current <= 0x4B:
                n = current
                if i + n > length:
                    raise VMError("Out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n
            # OP_PUSHDATA1 (0x4c)
            elif current == 0x4C:
                if i > length:
                    raise VMError("Missing length byte")
                n = raw[i]
                i += 1

                if i + n > length:
                    raise VMError("Out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n
            # OP_PUSHDATA2 (0x4d)
            elif current == 0x4D:
                if i + 1 >= length:
                    raise VMError("Missing length byte")

                n = int.from_bytes(raw[i : i + 2], "little")
                i += 2

                if i + n > length:
                    raise VMError("Out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n
            # OP_PUSHDATA4 (0x4e)
            elif current == 0x4E:
                if i + 3 >= length:
                    raise VMError("Missing length byte")

                n = int.from_bytes(raw[i : i + 4], "little")
                i += 4

                if i + n > length:
                    raise VMError("Out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n
            # other opcodes
            else:
                cmds.append(current)

        return cls(cmds)

    def serialize(self) -> bytes:
        result = b""
        for cmd in self.cmds:
            if isinstance(cmd, int):
                result += bytes([cmd])
            elif isinstance(cmd, bytes):
                length = len(cmd)
                if length < 0x4C:
                    result += bytes([length])
                elif length <= 0xFF:
                    result += bytes([0x4C, length])
                elif length <= 0xFFFF:
                    result += bytes([0x4D]) + length.to_bytes(2, "little")
                else:
                    result += bytes([0x4E]) + length.to_bytes(4, "little")
                result += cmd
        return result


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
        "OP_2\n<{}>\n<{}> # pubkey1 pubkey2 ...\nOP_2\nOP_CHECKMULTISIG", pk1, pk2
    )
    redeem_script_bytes = Script.parse(redeem_script_asm).serialize()
    redeem_script_hash = hash160(redeem_script_bytes)

    scriptSig = generate_asm_script(
        "<{}>\n<{}> # sig1 sig2 ...\n{{\n{}\n}} # redeem script hex",
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
        "<{}> # sig\n{{\n{}\n}} # witness script", sig, witness_script_asm
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
        "<{}> # sig\n{{\n{}\n}} # witness script", sig, witness_script_asm
    )

    return ("", scriptPubkey, witness)
