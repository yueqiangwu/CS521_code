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
        raw_input = raw_input.strip()
        if raw_input.startswith("OP_") or " " in raw_input:
            return cls.parse_asm(raw_input)
        else:
            return cls.parse_hex(raw_input)

    @classmethod
    def parse_asm(cls, raw_input: str):
        if "," in raw_input:
            raw_input = raw_input.replace(",", " ")

        tokens = raw_input.split()
        cmds = []

        for token in tokens:
            # data
            if token.startswith("<") and token.endswith(">"):
                hex_data = token[1:-1]

                if len(hex_data) % 2 != 0:
                    raise ValueError(f"Invalid hex data: {token}")

                data = bytes.fromhex(hex_data)
                cmds.append(data)
            # opcode
            elif token.startswith("OP_"):
                opcode = op_2_opcode(token)
                
                if opcode is None:
                    raise ValueError(f"Unknown operation: {token}")
                cmds.append(opcode)
            # other hex
            else:
                try:
                    if token.startswith(("0x", "0X")):
                        hex_data = token[2:]
                    data = bytes.fromhex(hex_data)
                    cmds.append(data)
                except:
                    raise ValueError(f"Invalid token: {token}")

        return cls(cmds)

    @classmethod
    def parse_hex(cls, raw_input: str):
        raw = bytes.fromhex(raw_input)
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
                    raise ValueError("Out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n
            # OP_PUSHDATA1 (0x4c)
            elif current == 0x4C:
                if i > length:
                    raise ValueError("Missing length byte")
                n = raw[i]
                i += 1

                if i + n > length:
                    raise ValueError("Out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n
            # OP_PUSHDATA2 (0x4d)
            elif current == 0x4D:
                if i + 1 >= length:
                    raise ValueError("Missing length byte")

                n = int.from_bytes(raw[i : i + 2], "little")
                i += 2

                if i + n > length:
                    raise ValueError("Out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n
            # OP_PUSHDATA4 (0x4e)
            elif current == 0x4E:
                if i + 3 >= length:
                    raise ValueError("Missing length byte")

                n = int.from_bytes(raw[i : i + 4], "little")
                i += 4

                if i + n > length:
                    raise ValueError("Out of range")

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