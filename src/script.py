class Script:
    """
    Store Instruction Sequence
    """

    def __init__(self, cmds: list[bytes | int]):
        self.cmds = cmds

    def __repr__(self):
        res = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                res.append(f"OP_{cmd}")
            else:
                res.append(cmd.hex())
        return " ".join(res)

    @classmethod
    def parse(cls, raw_hex: str):
        """
        Parse a hexadecimal string into a list of instructions
        """
        raw = bytes.fromhex(raw_hex)
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
                    raise ValueError("out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n

            # OP_PUSHDATA1 (0x4c)
            elif current == 0x4C:
                if i > length:
                    raise ValueError("missing length byte")
                n = raw[i]
                i += 1

                if i + n > length:
                    raise ValueError("out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n

            # OP_PUSHDATA2 (0x4d)
            elif current == 0x4D:
                if i + 1 >= length:
                    raise ValueError("missing length byte")

                n = int.from_bytes(raw[i : i + 2], "little")
                i += 2

                if i + n > length:
                    raise ValueError("out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n

            # OP_PUSHDATA4 (0x4e)
            elif current == 0x4E:
                if i + 3 >= length:
                    raise ValueError("missing length byte")

                n = int.from_bytes(raw[i : i + 4], "little")
                i += 4

                if i + n > length:
                    raise ValueError("out of range")

                data = raw[i : i + n]
                cmds.append(data)
                i += n

            # other opcodes
            else:
                cmds.append(current)

        return cls(cmds)
