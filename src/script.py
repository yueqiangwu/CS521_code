import re

from common import VMError
from opcodes import op_2_opcode


class Script:
    """
    Store instruction sequence
    """

    def __init__(self, cmds: list[bytes | int] | None = None):
        self.cmds = cmds or []

    def __repr__(self):
        res = []

        for cmd in self.cmds:
            if isinstance(cmd, int):
                res.append(f"OP_{cmd}")
            else:
                res.append(cmd.hex())

        return " ".join(res)

    @classmethod
    def parse(cls, raw_input: str):
        """
        Parse the input HEX/ASM string into a list of instructions
        """
        # remove notes
        lines = raw_input.split("\n")
        cleaned_content = " ".join(line.split("#")[0].strip() for line in lines)
        if not cleaned_content:
            return cls([])

        # Determine if it is ASM
        if any(x in cleaned_content for x in ["OP_", " ", "{", "}", "<", ">", "#"]):
            return cls.parse_asm(cleaned_content)
        else:
            return cls.parse_hex(cleaned_content)

    @classmethod
    def parse_asm(cls, raw_input: str):
        # Valid token: OP_xxx, <hex> / hex, {nested script}
        pattern = r"\{.*?\}|<.*?>|OP_\w+|\S+"
        tokens = re.findall(pattern, raw_input)

        cmds = []

        for token in tokens:
            # Handling nested ASM blocks
            if token.startswith("{") and token.endswith("}"):
                inner_asm = token[1:-1]
                inner_script = cls.parse_asm(inner_asm)
                cmds.append(inner_script.serialize())
            # Handling data
            elif token.startswith("<") and token.endswith(">"):
                try:
                    cmds.append(bytes.fromhex(token[1:-1]))
                except Exception:
                    raise VMError(f"Invalid hex data: {token}")
            # Handling opcode
            elif token.upper().startswith("OP_"):
                opcode = op_2_opcode(token)
                if opcode is None:
                    raise VMError(f"Unknown operation: {token}")

                cmds.append(opcode)
            # other hex
            else:
                try:
                    cmds.append(bytes.fromhex(token))
                except Exception:
                    raise VMError(f"Invalid token in ASM: {token}")

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
