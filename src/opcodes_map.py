OPCODES_MAP = {}


def opcode(code):
    def decorator(func):
        OPCODES_MAP[code] = func
        return func

    return decorator
