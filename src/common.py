VM_TRUE = b"\x01"
VM_FALSE = b"\x00"


class VMError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return f"Transaction failed: {self.message}"
