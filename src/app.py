import uuid
import os
import logging

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from common import TX_HASH_SIZE, VMError
from crypto import hash160, sha256, generate_sig_pair
from engine import BitcoinScriptInterpreter
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


sessions: dict[str, BitcoinScriptInterpreter] = {}


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
                vm = BitcoinScriptInterpreter(
                    Script.parse(f"{scriptSig}\n{scriptPubkey}"),
                    [],
                    Script.parse(witness).cmds,
                    tx_hash_bytes,
                )
            else:
                vm = BitcoinScriptInterpreter(vm.script, [], vm.witness, vm.tx_sig_hash)
            sessions[sid] = vm
        # step back
        case -1:
            if vm is None:
                vm = BitcoinScriptInterpreter(
                    Script.parse(f"{scriptSig}\n{scriptPubkey}"),
                    [],
                    Script.parse(witness).cmds,
                    tx_hash_bytes,
                )
                sessions[sid] = vm
            else:
                current_pc = vm.pc
                if current_pc != 0:
                    vm = BitcoinScriptInterpreter(
                        vm.script, [], vm.witness, vm.tx_sig_hash
                    )
                    for _ in range(current_pc - 1):
                        vm.step()
                    sessions[sid] = vm
        # step over
        case 1:
            if vm is None:
                vm = BitcoinScriptInterpreter(
                    Script.parse(f"{scriptSig}\n{scriptPubkey}"),
                    [],
                    Script.parse(witness).cmds,
                    tx_hash_bytes,
                )
                sessions[sid] = vm
            vm.step()
        # run all
        case 10:
            if vm is None:
                vm = BitcoinScriptInterpreter(
                    Script.parse(f"{scriptSig}\n{scriptPubkey}"),
                    [],
                    Script.parse(witness).cmds,
                    tx_hash_bytes,
                )
                sessions[sid] = vm
            while not vm.terminated:
                vm.step()
        case _:
            raise ValueError(f"Unknown mode: {mode}")

    active_vm = vm.active_inner_vm if vm.active_inner_vm else vm
    instructions = []
    for cmd in active_vm.script.cmds:
        instructions.append(opcode_2_op(cmd) if isinstance(cmd, int) else cmd.hex())
    stack = [x.hex() if isinstance(x, bytes) else str(x) for x in active_vm.stack]

    return jsonify(
        {
            "pc": active_vm.pc,
            "isInner": vm.active_inner_vm is not None,
            "isTerminated": vm.terminated,
            "isValid": vm._is_valid() if vm.terminated else None,
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
            res = input_text_bytes.decode()
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
    # app.run(debug=True, port=5000)
    app.run(debug=False, port=5000)
