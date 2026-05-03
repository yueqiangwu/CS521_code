from common import VM_TRUE, VM_FALSE, VMError
from crypto import (
    ripemd160,
    sha1,
    sha256,
    hash160,
    hash256,
    verify_sig,
    verify_multisig,
    verify_schnorr,
)
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from engine import BitcoinScriptInterpreter


# 0x63: IF, 0x64: NOTIF, 0x67: ELSE, 0x68: ENDIF
CONTROL_OPS: set[int] = {0x63, 0x64, 0x67, 0x68}

OP_OPCODE_MAP: dict[str, int] = {}
OPCODE_OP_MAP: dict[int, str] = {}
OPCODE_FUNC_MAP: dict[int, Callable] = {}


def op_2_opcode(op: str) -> int | None:
    return OP_OPCODE_MAP.get(op.upper())


def opcode_2_op(opcode: int) -> str | None:
    return OPCODE_OP_MAP.get(opcode)


def opcode(code: int):
    def wrapper(func):
        if code in OPCODE_OP_MAP.keys() or code in OPCODE_FUNC_MAP.keys():
            raise ValueError(f"Opcode {code} already registered")

        op = func.__name__
        op = op.upper()

        if op in OP_OPCODE_MAP.keys():
            raise ValueError(f"Operation {op} already registered")

        OP_OPCODE_MAP[op] = code
        op_short = op[3:]
        if not op_short.isdigit():
            OP_OPCODE_MAP[op_short] = code
        OPCODE_OP_MAP[code] = op
        OPCODE_FUNC_MAP[code] = func

        return func

    return wrapper


# ---------- Helper functions ----------


def int_to_scriptnum(n: int) -> bytes:
    if n == 0:
        return b""

    abs_n = abs(n)
    res = []
    while abs_n:
        res.append(abs_n & 0xFF)
        abs_n >>= 8

    if res[-1] & 0x80:
        res.append(0x80 if n < 0 else 0x00)
    elif n < 0:
        res[-1] |= 0x80

    return bytes(res)


def scriptnum_to_int(data: bytes) -> int:
    if not data:
        return 0

    if data == b"\x80":
        return 0

    last_byte = data[-1]
    is_negative = bool(last_byte & 0x80)

    if is_negative:
        modified_last_byte = last_byte & 0x7F
        data_to_decode = data[:-1] + bytes([modified_last_byte])
    else:
        data_to_decode = data

    val = int.from_bytes(data_to_decode, "little")
    return -val if is_negative else val


def is_true(data: bytes) -> bool:
    """
    Truthiness evaluation in Bitcoin Scripts
    """
    if not data:
        return False
    if data in [VM_FALSE, b"\x80"]:
        return False
    return any(b != 0 for b in data)


# ---------- Constants ----------


@opcode(0x00)
def op_0(vm: "BitcoinScriptInterpreter"):
    vm.push(int_to_scriptnum(0))


OP_OPCODE_MAP["OP_FALSE"] = 0x00
OP_OPCODE_MAP["FALSE"] = 0x00


@opcode(0x4F)
def op_1negate(vm: "BitcoinScriptInterpreter"):
    vm.push(int_to_scriptnum(-1))


def _register_small_ints():
    def create_op_func(i):
        def op_func(vm: "BitcoinScriptInterpreter"):
            vm.push(int_to_scriptnum(i))

        return op_func

    for i in range(1, 17):
        code = 0x50 + i
        op_name = f"OP_{i}"
        func = create_op_func(i)

        OP_OPCODE_MAP[op_name] = code
        OPCODE_OP_MAP[code] = op_name
        OPCODE_FUNC_MAP[code] = func

        if i == 1:
            OP_OPCODE_MAP["OP_TRUE"] = code
            OP_OPCODE_MAP["TRUE"] = code


_register_small_ints()


# ---------- Flow control ----------


@opcode(0x61)
def op_nop(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0x62)
def op_ver(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0x63)
def op_if(vm: "BitcoinScriptInterpreter"):
    if not all(vm.vf_stack):
        vm.vf_stack.append(False)
        return

    data = vm.pop()
    vm.vf_stack.append(is_true(data))


@opcode(0x64)
def op_notif(vm: "BitcoinScriptInterpreter"):
    if not all(vm.vf_stack):
        vm.vf_stack.append(False)
        return

    data = vm.pop()
    vm.vf_stack.append(not is_true(data))


@opcode(0x65)
def op_verif(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0x66)
def op_vernotif(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0x67)
def op_else(vm: "BitcoinScriptInterpreter"):
    if not vm.vf_stack:
        raise VMError("OP_ELSE without OP_IF")

    if all(vm.vf_stack[:-1]):
        vm.vf_stack[-1] = not vm.vf_stack[-1]


@opcode(0x68)
def op_endif(vm: "BitcoinScriptInterpreter"):
    if not vm.vf_stack:
        raise VMError("OP_ENDIF without OP_IF")

    vm.vf_stack.pop()


@opcode(0x69)
def op_verify(vm: "BitcoinScriptInterpreter"):
    data = vm.pop()
    if not is_true(data):
        raise VMError("OP_VERIFY failed")


@opcode(0x6A)
def op_return(vm: "BitcoinScriptInterpreter"):
    vm.is_terminated = True


# ---------- Stack ----------


@opcode(0x6B)
def op_toaltstack(vm: "BitcoinScriptInterpreter"):
    vm.alt_stack.append(vm.pop())


@opcode(0x6C)
def op_fromaltstack(vm: "BitcoinScriptInterpreter"):
    if len(vm.alt_stack) < 1:
        raise VMError("Alt stack underflow")
    vm.push(vm.alt_stack.pop())


@opcode(0x6D)
def op_2drop(vm: "BitcoinScriptInterpreter"):
    vm.pop()
    vm.pop()


@opcode(0x6E)
def op_2dup(vm: "BitcoinScriptInterpreter"):
    if len(vm.stack) < 2:
        raise VMError("Stack underflow")
    v1, v2 = vm.stack[-2], vm.stack[-1]
    vm.push(v1)
    vm.push(v2)


@opcode(0x6F)
def op_3dup(vm: "BitcoinScriptInterpreter"):
    if len(vm.stack) < 3:
        raise VMError("Stack underflow")
    v1, v2, v3 = vm.stack[-3], vm.stack[-2], vm.stack[-1]
    vm.push(v1)
    vm.push(v2)
    vm.push(v3)


@opcode(0x70)
def op_2over(vm: "BitcoinScriptInterpreter"):
    if len(vm.stack) < 4:
        raise VMError("Stack underflow")
    v1, v2 = vm.stack[-4], vm.stack[-3]
    vm.push(v1)
    vm.push(v2)


@opcode(0x71)
def op_2rot(vm: "BitcoinScriptInterpreter"):
    if len(vm.stack) < 6:
        raise VMError("Stack underflow")
    v1 = vm.stack.pop(-6)
    v2 = vm.stack.pop(-5)
    vm.push(v1)
    vm.push(v2)


@opcode(0x72)
def op_2swap(vm: "BitcoinScriptInterpreter"):
    if len(vm.stack) < 4:
        raise VMError("Stack underflow")
    # x1 x2 x3 x4 -> x3 x4 x1 x2
    v4, v3, v2, v1 = vm.pop(), vm.pop(), vm.pop(), vm.pop()
    vm.push(v3)
    vm.push(v4)
    vm.push(v1)
    vm.push(v2)


@opcode(0x73)
def op_ifdup(vm: "BitcoinScriptInterpreter"):
    data = vm.top()
    if is_true(data):
        vm.push(data)


@opcode(0x74)
def op_depth(vm: "BitcoinScriptInterpreter"):
    depth = len(vm.stack)
    vm.push(int_to_scriptnum(depth))


@opcode(0x75)
def op_drop(vm: "BitcoinScriptInterpreter"):
    vm.pop()


@opcode(0x76)
def op_dup(vm: "BitcoinScriptInterpreter"):
    data = vm.top()
    vm.push(data)


@opcode(0x77)
def op_nip(vm: "BitcoinScriptInterpreter"):
    # x1 x2 -> x2
    if len(vm.stack) < 2:
        raise VMError("Stack underflow")
    vm.stack.pop(-2)


@opcode(0x78)
def op_over(vm: "BitcoinScriptInterpreter"):
    if len(vm.stack) < 2:
        raise VMError("Stack underflow")
    vm.push(vm.stack[-2])


@opcode(0x79)
def op_pick(vm: "BitcoinScriptInterpreter"):
    n = scriptnum_to_int(vm.pop())
    if len(vm.stack) <= n or n < 0:
        raise VMError("Pick out of range")
    vm.push(vm.stack[-(n + 1)])


@opcode(0x7A)
def op_roll(vm: "BitcoinScriptInterpreter"):
    n = scriptnum_to_int(vm.pop())
    if len(vm.stack) <= n or n < 0:
        raise VMError("Roll out of range")
    item = vm.stack.pop(-(n + 1))
    vm.push(item)


@opcode(0x7B)
def op_rot(vm: "BitcoinScriptInterpreter"):
    # x1 x2 x3 -> x2 x3 x1
    if len(vm.stack) < 3:
        raise VMError("Stack underflow")
    x3, x2, x1 = vm.pop(), vm.pop(), vm.pop()
    vm.push(x2)
    vm.push(x3)
    vm.push(x1)


@opcode(0x7C)
def op_swap(vm: "BitcoinScriptInterpreter"):
    if len(vm.stack) < 2:
        raise VMError("Stack underflow")
    x2, x1 = vm.pop(), vm.pop()
    vm.push(x2)
    vm.push(x1)


@opcode(0x7D)
def op_tuck(vm: "BitcoinScriptInterpreter"):
    # x1 x2 -> x2 x1 x2
    if len(vm.stack) < 2:
        raise VMError("Stack underflow")
    x2 = vm.pop()
    x1 = vm.pop()
    vm.push(x2)
    vm.push(x1)
    vm.push(x2)


# ---------- Data Manipulation ----------


@opcode(0x7E)
def op_cat(vm: "BitcoinScriptInterpreter"):
    x2 = vm.pop()
    x1 = vm.pop()
    vm.push(x1 + x2)


@opcode(0x7F)
def op_split(vm: "BitcoinScriptInterpreter"):
    n = scriptnum_to_int(vm.pop())
    x = vm.pop()
    if n < 0 or n > len(x):
        raise VMError("OP_SPLIT: Invalid split index")

    vm.push(x[:n])
    vm.push(x[n:])


@opcode(0x80)
def op_num2bin(vm: "BitcoinScriptInterpreter"):
    size = scriptnum_to_int(vm.pop())
    val = scriptnum_to_int(vm.pop())

    if size < 0 or size > 520:
        raise VMError("OP_NUM2BIN: Invalid size")

    res = val.to_bytes(size, "little", signed=True)
    vm.push(res)


@opcode(0x81)
def op_bin2num(vm: "BitcoinScriptInterpreter"):
    x = vm.pop()
    val = scriptnum_to_int(x)
    vm.push(int_to_scriptnum(val))


@opcode(0x82)
def op_size(vm: "BitcoinScriptInterpreter"):
    data = vm.top()
    length = len(data)
    vm.push(int_to_scriptnum(length))


# ---------- Bitwise logic ----------


@opcode(0x83)
def op_invert(vm: "BitcoinScriptInterpreter"):
    data = vm.pop()
    res = bytes([~b & 0xFF for b in data])
    vm.push(res)


@opcode(0x84)
def op_and(vm: "BitcoinScriptInterpreter"):
    x2 = vm.pop()
    x1 = vm.pop()
    if len(x1) != len(x2):
        raise VMError("OP_AND: Operands must have the same length")

    res = bytes([b1 & b2 for b1, b2 in zip(x1, x2)])
    vm.push(res)


@opcode(0x85)
def op_or(vm: "BitcoinScriptInterpreter"):
    x2 = vm.pop()
    x1 = vm.pop()
    if len(x1) != len(x2):
        raise VMError("OP_OR: Operands must have the same length")

    res = bytes([b1 | b2 for b1, b2 in zip(x1, x2)])
    vm.push(res)


@opcode(0x86)
def op_xor(vm: "BitcoinScriptInterpreter"):
    x2 = vm.pop()
    x1 = vm.pop()
    if len(x1) != len(x2):
        raise VMError("OP_XOR: Operands must have the same length")

    res = bytes([b1 ^ b2 for b1, b2 in zip(x1, x2)])
    vm.push(res)


@opcode(0x87)
def op_equal(vm: "BitcoinScriptInterpreter"):
    data_1 = vm.pop()
    data_2 = vm.pop()
    if data_1 == data_2:
        vm.push(VM_TRUE)
    else:
        vm.push(VM_FALSE)


@opcode(0x88)
def op_equalverify(vm: "BitcoinScriptInterpreter"):
    op_equal(vm)
    if not is_true(vm.pop()):
        raise VMError("OP_EQUALVERIFY failed")


# ---------- Arithmetic ----------


@opcode(0x8B)
def op_1add(vm: "BitcoinScriptInterpreter"):
    val = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(val + 1))


@opcode(0x8C)
def op_1sub(vm: "BitcoinScriptInterpreter"):
    val = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(val - 1))


@opcode(0x8F)
def op_negate(vm: "BitcoinScriptInterpreter"):
    val = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(-val))


@opcode(0x90)
def op_abs(vm: "BitcoinScriptInterpreter"):
    val = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(abs(val)))


@opcode(0x91)
def op_not(vm: "BitcoinScriptInterpreter"):
    val = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(1 if val == 0 else 0))


@opcode(0x92)
def op_0notequal(vm: "BitcoinScriptInterpreter"):
    val = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(1 if val != 0 else 0))


@opcode(0x93)
def op_add(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(a + b))


@opcode(0x94)
def op_sub(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(a - b))


@opcode(0x95)
def op_mul(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(a * b))


@opcode(0x96)
def op_div(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    if b == 0:
        raise VMError("Division by zero")
    a = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(a // b))


@opcode(0x97)
def op_mod(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    if b == 0:
        raise VMError("Division by zero")
    a = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(a % b))


@opcode(0x98)
def op_lshift(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(a << b))


@opcode(0x99)
def op_rshift(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(a >> b))


@opcode(0x9A)
def op_booland(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(VM_TRUE if a != 0 and b != 0 else VM_FALSE)


@opcode(0x9B)
def op_boolor(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(VM_TRUE if a != 0 or b != 0 else VM_FALSE)


@opcode(0x9C)
def op_numequal(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(VM_TRUE if a == b else VM_FALSE)


@opcode(0x9D)
def op_numequalverify(vm: "BitcoinScriptInterpreter"):
    op_numequal(vm)
    if is_true(vm.pop()):
        raise VMError("OP_NUMEQUALVERIFY failed")


@opcode(0x9E)
def op_numnotequal(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(VM_TRUE if a != b else VM_FALSE)


@opcode(0x9F)
def op_lessthan(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(VM_TRUE if a < b else VM_FALSE)


@opcode(0xA0)
def op_greaterthan(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(VM_TRUE if a > b else VM_FALSE)


@opcode(0xA1)
def op_lessthanorequal(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(VM_TRUE if a <= b else VM_FALSE)


@opcode(0xA2)
def op_greaterthanorequal(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(VM_TRUE if a >= b else VM_FALSE)


@opcode(0xA3)
def op_min(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(min(a, b)))


@opcode(0xA4)
def op_max(vm: "BitcoinScriptInterpreter"):
    b = scriptnum_to_int(vm.pop())
    a = scriptnum_to_int(vm.pop())
    vm.push(int_to_scriptnum(max(a, b)))


@opcode(0xA5)
def op_within(vm: "BitcoinScriptInterpreter"):
    max_val = scriptnum_to_int(vm.pop())
    min_val = scriptnum_to_int(vm.pop())
    x = scriptnum_to_int(vm.pop())
    vm.push(VM_TRUE if min_val <= x < max_val else VM_FALSE)


# ---------- Cryptography ----------


@opcode(0xA6)
def op_ripemd160(vm: "BitcoinScriptInterpreter"):
    vm.push(ripemd160(vm.pop()))


@opcode(0xA7)
def op_sha1(vm: "BitcoinScriptInterpreter"):
    vm.push(sha1(vm.pop()))


@opcode(0xA8)
def op_sha256(vm: "BitcoinScriptInterpreter"):
    vm.push(sha256(vm.pop()))


@opcode(0xA9)
def op_hash160(vm: "BitcoinScriptInterpreter"):
    vm.push(hash160(vm.pop()))


@opcode(0xAA)
def op_hash256(vm: "BitcoinScriptInterpreter"):
    vm.push(hash256(vm.pop()))


@opcode(0xAB)
def op_codeseparator(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0xAC)
def op_checksig(vm: "BitcoinScriptInterpreter"):
    pubkey = vm.pop()
    signature = vm.pop()
    # 32-byte x-only pubkey → BIP340 Schnorr; 33-byte compressed → ECDSA
    if len(pubkey) == 32:
        result = verify_schnorr(pubkey, signature, vm.tx_sig_hash)
    else:
        result = verify_sig(pubkey, signature, vm.tx_sig_hash)
    vm.push(VM_TRUE if result else VM_FALSE)


@opcode(0xAD)
def op_checksigverify(vm: "BitcoinScriptInterpreter"):
    op_checksig(vm)
    if is_true(vm.pop()):
        raise VMError("OP_CHECKSIGVERIFY failed")


@opcode(0xAE)
def op_checkmultisig(vm: "BitcoinScriptInterpreter"):
    n_pub = scriptnum_to_int(vm.pop())
    pubkeys = [vm.pop() for _ in range(n_pub)]
    pubkeys.reverse()

    n_sig = scriptnum_to_int(vm.pop())
    sigs = [vm.pop() for _ in range(n_sig)]
    sigs.reverse()

    # vm.pop()

    success = verify_multisig(pubkeys, sigs, vm.tx_sig_hash)
    vm.push(VM_TRUE if success else VM_FALSE)


@opcode(0xAF)
def op_checkmultisigverify(vm: "BitcoinScriptInterpreter"):
    op_checkmultisig(vm)
    if is_true(vm.pop()):
        raise VMError("OP_CHECKMULTISIGVERIFY failed")


@opcode(0xBA)
def op_checksigadd(vm: "BitcoinScriptInterpreter"):
    """BIP342 Tapscript: pop pubkey, n, sig; push n+1 if sig valid, n if sig empty, fail otherwise."""
    pubkey = vm.pop()
    n_bytes = vm.pop()
    sig = vm.pop()

    n = int.from_bytes(n_bytes, "little") if n_bytes else 0

    if not sig:
        vm.push(n_bytes)
        return

    if len(pubkey) == 32:
        result = verify_schnorr(pubkey, sig, vm.tx_sig_hash)
    else:
        result = verify_sig(pubkey, sig, vm.tx_sig_hash)

    if not result:
        raise VMError("OP_CHECKSIGADD: non-empty signature failed verification")

    new_n = n + 1
    vm.push(new_n.to_bytes((new_n.bit_length() + 7) // 8, "little"))


# ---------- Used NOP opcode identifiers ----------
@opcode(0xB1)
def op_nop2(vm: "BitcoinScriptInterpreter"):
    pass


OP_OPCODE_MAP["OP_CHECKLOCKTIMEVERIFY"] = 0xB1
OP_OPCODE_MAP["CHECKLOCKTIMEVERIFY"] = 0xB1


@opcode(0xB2)
def op_nop3(vm: "BitcoinScriptInterpreter"):
    pass


OP_OPCODE_MAP["OP_CHECKSEQUENCEVERIFY"] = 0xB2
OP_OPCODE_MAP["CHECKSEQUENCEVERIFY"] = 0xB2


# ---------- Reserved words ----------


@opcode(0x50)
def op_reserved(vm: "BitcoinScriptInterpreter"):
    raise VMError("OP_RESERVED: Transaction is invalid")


@opcode(0x89)
def op_reserved1(vm: "BitcoinScriptInterpreter"):
    raise VMError("OP_RESERVED1: Transaction is invalid")


@opcode(0x8A)
def op_reserved2(vm: "BitcoinScriptInterpreter"):
    raise VMError("OP_RESERVED2: Transaction is invalid")


@opcode(0xB0)
def op_nop1(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0xB3)
def op_nop4(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0xB4)
def op_nop5(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0xB5)
def op_nop6(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0xB6)
def op_nop7(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0xB7)
def op_nop8(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0xB8)
def op_nop9(vm: "BitcoinScriptInterpreter"):
    pass


@opcode(0xB9)
def op_nop10(vm: "BitcoinScriptInterpreter"):
    pass
