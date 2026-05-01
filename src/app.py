import uuid
import os
import logging

from cachetools import TTLCache
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from common import TX_HASH_SIZE, VMError
from crypto import hash160, sha256, generate_sig_pair
from engine_v2 import BitcoinScriptInterpreterV2
from opcodes import opcode_2_op
from script import Script
from templates import generate_template

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s - %(message)s",
)

app = Flask(__name__)
CORS(app)


@app.errorhandler(Exception)
def handle_exception(e):
    """
    Catch all unhandled exceptions.
    """
    if isinstance(e, VMError):
        return jsonify(e.to_dict()), e.status_code

    if isinstance(e, HTTPException):
        return jsonify({"message": e.description, "status": "error"}), e.code

    logging.error("Internal Error: ", e)
    return jsonify({"message": str(e), "status": "error"}), 500


# sessions: dict[str, BitcoinScriptInterpreterV2] = {}
sessions = TTLCache(maxsize=5000, ttl=30 * 60)


@app.route("/api/init", methods=["POST"])
def init_session():
    """
    Initializes a session, generates a random TxHash, and returns the session_id
    """
    session_id = str(uuid.uuid4())
    tx_hash = os.urandom(TX_HASH_SIZE)

    return jsonify({"sessionId": session_id, "txHash": tx_hash.hex()})


@app.route("/api/templates/options", methods=["GET"])
def get_templates_options():
    """
    Return template options
    """
    templates_options: list[str] = ["P2PK", "P2PKH", "P2SH", "P2WPKH", "P2WSH"]

    return jsonify({"templatesOptions": templates_options})


@app.route("/api/templates", methods=["GET"])
def get_templates():
    """
    Return the chosen template
    """
    transaction_type = request.args.get("transactionType")
    tx_hash = request.args.get("txHash", "")

    try:
        tx_hash_bytes = bytes.fromhex(tx_hash)
    except Exception:
        raise VMError(f"Invalid hex string: {tx_hash}", status_code=401)

    scriptSig, scriptPubkey, witness = generate_template(
        transaction_type, tx_hash_bytes
    )

    return jsonify(
        {"scriptSig": scriptSig, "scriptPubkey": scriptPubkey, "witness": witness}
    )


@app.route("/api/step", methods=["POST"])
def step_vm():
    """
    Run Bitcoin script interpreter based on mode
    """
    data = request.json
    sid = data.get("sessionId")
    mode = data.get("mode")
    tx_hash = data.get("txHash", "")
    scriptSig = data.get("scriptSig", "")
    scriptPubkey = data.get("scriptPubkey", "")
    witness = data.get("witness", "")

    try:
        tx_hash_bytes = bytes.fromhex(tx_hash)
    except Exception:
        raise VMError(f"Invalid hex string: {tx_hash}", status_code=401)

    vm = sessions.get(sid)
    match mode:
        # reset
        case -10:
            if vm is None:
                vm = BitcoinScriptInterpreterV2(
                    tx_hash_bytes,
                    Script.parse(scriptSig),
                    Script.parse(scriptPubkey),
                    Script.parse(witness),
                )
            else:
                vm = BitcoinScriptInterpreterV2(
                    vm.tx_sig_hash, vm.script_sig, vm.script_pubkey, vm.witness
                )
            sessions[sid] = vm
        # step back
        case -1:
            if vm is None:
                vm = BitcoinScriptInterpreterV2(
                    tx_hash_bytes,
                    Script.parse(scriptSig),
                    Script.parse(scriptPubkey),
                    Script.parse(witness),
                )
                sessions[sid] = vm
            else:
                current_pc = vm.pc
                if current_pc != 0:
                    vm = BitcoinScriptInterpreterV2(
                        vm.tx_sig_hash, vm.script_sig, vm.script_pubkey, vm.witness
                    )
                    while vm.pc < current_pc - 1:
                        vm.step()
                    sessions[sid] = vm
        # step over
        case 1:
            if vm is None:
                vm = BitcoinScriptInterpreterV2(
                    tx_hash_bytes,
                    Script.parse(scriptSig),
                    Script.parse(scriptPubkey),
                    Script.parse(witness),
                )
                sessions[sid] = vm
            # initialize also counts as one step
            else:
                vm.step()
        # run all
        case 10:
            if vm is None:
                vm = BitcoinScriptInterpreterV2(
                    tx_hash_bytes,
                    Script.parse(scriptSig),
                    Script.parse(scriptPubkey),
                    Script.parse(witness),
                )
                sessions[sid] = vm
            while not vm.is_terminated:
                vm.step()
        case _:
            raise ValueError(f"Unknown mode: {mode}")

    instructions = []
    for cmd, instr_type in zip(vm.instructions, vm.instr_types):
        instructions.append(
            {
                "instr": opcode_2_op(cmd) if isinstance(cmd, int) else cmd.hex(),
                "instrType": instr_type.value,
            }
        )
    stack = [x.hex() if isinstance(x, bytes) else str(x) for x in vm.stack]

    return jsonify(
        {
            "transType": vm.trans_type.value,
            "pc": vm.pc,
            "isTerminated": vm.is_terminated,
            "isValid": vm.is_valid() if vm.is_terminated else None,
            "instructions": instructions,
            "stack": stack,
        }
    )


@app.route("/api/clear", methods=["POST"])
def clear_vm():
    """
    Delete current Bitcoin script interpreter
    """
    data = request.json
    sid = data.get("sessionId")

    if sid in sessions:
        del sessions[sid]

    return jsonify({"success": True})


@app.route("/api/utils/string", methods=["GET"])
def util_string():
    """
    Utility tool for string transformations
    """
    input_text = request.args.get("inputText", "")
    mode = request.args.get("mode")

    match mode:
        case "sha256":
            try:
                input_text_bytes = bytes.fromhex(input_text)
            except Exception:
                raise VMError(f"Invalid hex string: {input_text}", status_code=401)
            res = sha256(input_text_bytes).hex()
        case "hash160":
            try:
                input_text_bytes = bytes.fromhex(input_text)
            except Exception:
                raise VMError(f"Invalid hex string: {input_text}", status_code=401)
            res = hash160(input_text_bytes).hex()
        case "str2hex":
            res = input_text.encode().hex()
        case "hex2str":
            try:
                input_text_bytes = bytes.fromhex(input_text)
            except Exception:
                raise VMError(f"Invalid hex string: {input_text}", status_code=401)
            try:
                res = input_text_bytes.decode()
            except Exception:
                raise VMError(
                    f"Hex string cannot be decoded: {input_text}", status_code=401
                )
        case "asm2hex":
            res = Script.parse(input_text).serialize().hex()
        case "hex2asm":
            cmds = Script.parse_hex(input_text).cmds
            instructions = []
            for cmd in cmds:
                instructions.append(
                    opcode_2_op(cmd) if isinstance(cmd, int) else cmd.hex()
                )
            res = "\n".join(instructions)
        case _:
            raise ValueError(f"Unknown mode: {mode}")

    return jsonify({"result": res})


@app.route("/api/utils/sig", methods=["GET"])
def util_sig():
    """
    Utility tool for generating random pair(sig, pubkey) using given TX hash
    """
    tx_hash = request.args.get("txHash", "")
    try:
        tx_hash_bytes = bytes.fromhex(tx_hash)
    except Exception:
        raise VMError(f"Invalid hex string: {tx_hash}", status_code=401)

    pk, sig = generate_sig_pair(tx_hash_bytes)

    return jsonify({"sig": sig.hex(), "pubKey": pk.hex()})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
    # app.run(debug=False, port=5000)
