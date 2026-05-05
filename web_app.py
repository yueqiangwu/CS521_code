"""
Bitcoin UTXO Visualizer — Flask backend

Run:  python web_app.py
Then open http://localhost:5000
"""

import logging
import os
import uuid
import sys
import traceback

sys.path.insert(0, "src")

from cachetools import TTLCache
from ecdsa import SigningKey, SECP256k1
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from common import TX_HASH_SIZE, VMError
from crypto import hash160, sha256, generate_sig_pair
from engine_v2 import BitcoinScriptInterpreterV2
from opcodes import opcode_2_op
from script import Script, generate_template
from utxo import UTXOSet, TxInput, TxOutput, Transaction, UTXO

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s - %(message)s",
)

app = Flask(__name__)
CORS(app)


# ---------- Bircoin Script Interpreter Part Start ----------


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
    alt_stack = [x.hex() if isinstance(x, bytes) else str(x) for x in vm.alt_stack]
    vf_stack = vm.vf_stack

    return jsonify(
        {
            "transType": vm.trans_type.value,
            "pc": vm.pc,
            "isTerminated": vm.is_terminated,
            "isValid": vm.is_valid() if vm.is_terminated else None,
            "instructions": instructions,
            "stack": stack,
            "altStack": alt_stack,
            "vfStack": vf_stack,
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
            res = Script._asm_to_hex_bytes(input_text).hex()
        case "hex2asm":
            cmds = Script.parse_hex(input_text).cmds
            instructions = [
                opcode_2_op(cmd) if isinstance(cmd, int) else cmd.hex() for cmd in cmds
            ]
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


# ---------- Bircoin Script Interpreter Part End ----------


# ── Pre-loaded accounts ───────────────────────────────────────────────────


def _make_account(privkey_int: int):
    sk = SigningKey.from_string(privkey_int.to_bytes(32, "big"), curve=SECP256k1)
    pk = sk.get_verifying_key().to_string()
    ph = hash160(pk)
    return {
        "privkey_int": privkey_int,
        "pubkey": pk.hex(),
        "pubkey_hash": ph.hex(),
        "address": ph.hex()[:12] + "…",
    }


ACCOUNTS = {
    "Alice": _make_account(1),
    "Bob": _make_account(2),
    "Charlie": _make_account(3),
}

OWNER_COLORS = {"Alice": "primary", "Bob": "success", "Charlie": "warning"}


# ── Script factories ──────────────────────────────────────────────────────


def _p2pkh(pubkey: bytes) -> Script:
    h = hash160(pubkey)
    return Script.parse(f"OP_DUP OP_HASH160 <{h.hex()}> OP_EQUALVERIFY OP_CHECKSIG")


def _p2wpkh(pubkey: bytes) -> Script:
    return Script.parse(f"OP_0 <{hash160(pubkey).hex()}>")


def _multisig_redeem(m: int, signers: list[str]) -> bytes:
    """Serialize the bare M-of-N multisig script."""
    pubkeys = [bytes.fromhex(ACCOUNTS[s]["pubkey"]) for s in signers]
    n = len(signers)
    pk_items = " ".join(f"<{pk.hex()}>" for pk in pubkeys)
    return Script.parse(f"OP_{m} {pk_items} OP_{n} OP_CHECKMULTISIG").serialize()


def _p2sh_multisig(m: int, signers: list[str]) -> tuple[Script, bytes]:
    """Return (scriptPubKey, redeem_script_bytes) for P2SH M-of-N multisig."""
    rs_bytes = _multisig_redeem(m, signers)
    sh = hash160(rs_bytes)
    sp = Script.parse(f"OP_HASH160 <{sh.hex()}> OP_EQUAL")
    return sp, rs_bytes


def _p2wsh_multisig(m: int, signers: list[str]) -> tuple[Script, bytes]:
    """Return (scriptPubKey, witness_script_bytes) for P2WSH M-of-N multisig."""
    ws_bytes = _multisig_redeem(m, signers)
    sh = sha256(ws_bytes)
    sp = Script.parse(f"OP_0 <{sh.hex()}>")
    return sp, ws_bytes


def _bip143_script_code_p2wpkh(pubkey_hash: bytes) -> bytes:
    """BIP143 scriptCode for P2WPKH: the equivalent P2PKH script."""
    return bytes([0x76, 0xA9, 0x14]) + pubkey_hash + bytes([0x88, 0xAC])


SCRIPT_FACTORIES = {"P2PKH": _p2pkh, "P2WPKH": _p2wpkh}


# ── Script metadata helpers ───────────────────────────────────────────────


def _script_type(sp: Script) -> str:
    c = sp.cmds
    if len(c) == 5 and c[0] == 0x76:
        return "P2PKH"
    if len(c) == 2 and (c[0] == 0x00 or c[0] == b"\x00") and isinstance(c[1], bytes):
        return "P2WPKH" if len(c[1]) == 20 else "P2WSH"
    if len(c) == 2 and c[0] == 0x51:
        return "P2TR"
    if len(c) == 3 and c[0] == 0xA9 and isinstance(c[1], bytes):
        return "P2SH"
    return "Custom"


def _owner(sp: Script) -> str:
    """Return a human-readable owner label.  Multisig returns the first signer."""
    c = sp.cmds
    # P2SH — look up redeem-script registry
    if len(c) == 3 and c[0] == 0xA9 and isinstance(c[1], bytes) and c[2] == 0x87:
        sh = c[1].hex()
        if sh in multisig_info:
            return multisig_info[sh]["signers"][0]
        return "P2SH"
    # P2WSH — look up witness-script registry
    if (
        len(c) == 2
        and (c[0] == 0x00 or c[0] == b"\x00")
        and isinstance(c[1], bytes)
        and len(c[1]) == 32
    ):
        sh = c[1].hex()
        if sh in witness_script_info:
            return witness_script_info[sh]["signers"][0]
        return "P2WSH"
    # P2PKH / P2WPKH — match pubkey hash
    h = None
    if len(c) == 5 and c[0] == 0x76 and isinstance(c[2], bytes):
        h = c[2].hex()
    elif (
        len(c) == 2
        and (c[0] == 0x00 or c[0] == b"\x00")
        and isinstance(c[1], bytes)
        and len(c[1]) == 20
    ):
        h = c[1].hex()
    if h:
        for name, acct in ACCOUNTS.items():
            if acct["pubkey_hash"] == h:
                return name
    return "Unknown"


def _utxo_dict(u: UTXO) -> dict:
    stype = _script_type(u.script_pubkey)
    d = {
        "txid": u.txid.hex(),
        "txid_short": u.txid.hex()[:10] + "…",
        "vout": u.vout,
        "amount": u.amount,
        "script_type": stype,
        "owner": _owner(u.script_pubkey),
    }
    # Attach multisig metadata so the frontend can render co-owner badges
    if stype == "P2SH":
        c = u.script_pubkey.cmds
        if len(c) == 3 and isinstance(c[1], bytes):
            sh = c[1].hex()
            if sh in multisig_info:
                d["multisig"] = multisig_info[sh]  # {m, n, signers[, subtype]}
    elif stype == "P2WSH":
        c = u.script_pubkey.cmds
        if len(c) == 2 and isinstance(c[1], bytes):
            sh = c[1].hex()
            if sh in witness_script_info:
                d["multisig"] = witness_script_info[sh]
    return d


# ── Global state ──────────────────────────────────────────────────────────

utxo_set: UTXOSet = UTXOSet()
tx_history: list = []
redeem_scripts: dict[str, bytes] = {}  # hash160_hex → redeem_script_bytes  (P2SH)
multisig_info: dict[str, dict] = {}  # hash160_hex → {m, n, signers}       (P2SH)
witness_scripts: dict[str, bytes] = {}  # sha256_hex  → witness_script_bytes  (P2WSH)
witness_script_info: dict[str, dict] = {}  # sha256_hex  → {m, n, signers}       (P2WSH)

GENESIS_TXID = b"\x00" * 32


def _seed():
    global utxo_set, tx_history, redeem_scripts, multisig_info
    global witness_scripts, witness_script_info
    utxo_set = UTXOSet()
    tx_history = []
    redeem_scripts = {}
    multisig_info = {}
    witness_scripts = {}
    witness_script_info = {}
    alice_pk = bytes.fromhex(ACCOUNTS["Alice"]["pubkey"])
    bob_pk = bytes.fromhex(ACCOUNTS["Bob"]["pubkey"])
    charlie_pk = bytes.fromhex(ACCOUNTS["Charlie"]["pubkey"])
    utxo_set.add_coinbase(
        GENESIS_TXID,
        [
            TxOutput(100_000, _p2pkh(alice_pk)),
            TxOutput(75_000, _p2wpkh(bob_pk)),
            TxOutput(50_000, _p2pkh(charlie_pk)),
        ],
    )


_seed()


# ── Routes ────────────────────────────────────────────────────────────────


@app.route("/")
def index():
    return render_template("index.html", accounts=ACCOUNTS, owner_colors=OWNER_COLORS)


@app.route("/api/state")
def api_state():
    all_u = utxo_set.all_utxos()
    return jsonify(
        {
            "utxos": [_utxo_dict(u) for u in all_u],
            "total": sum(u.amount for u in all_u),
            "utxo_count": len(all_u),
            "tx_count": len(tx_history),
        }
    )


@app.route("/api/history")
def api_history():
    # Strip large fields (inputs_replay, raw_tx) from list; fetched on demand
    slim = [
        {k: v for k, v in r.items() if k not in ("inputs_replay", "raw_tx")}
        for r in tx_history[-30:]
    ]
    return jsonify({"history": slim})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    _seed()
    return jsonify({"ok": True})


@app.route("/api/create_multisig", methods=["POST"])
def api_create_multisig():
    """
    Body: {m: 2, signers: ["Alice", "Bob"], amount: 100000, script_type: "P2SH"|"P2WSH"}
    Creates a P2SH or P2WSH multisig UTXO and adds it to the UTXO pool.
    """
    body = request.get_json(force=True)
    m = int(body.get("m", 2))
    signers = body.get("signers", [])
    amount = int(body.get("amount", 100_000))
    script_type = body.get("script_type", "P2SH")

    if len(signers) < 2:
        return jsonify(
            {"success": False, "error": "Multisig requires at least 2 signers"}
        )
    if not 1 <= m <= len(signers):
        return jsonify(
            {"success": False, "error": f"Invalid threshold: {m}-of-{len(signers)}"}
        )
    unknown = [s for s in signers if s not in ACCOUNTS]
    if unknown:
        return jsonify(
            {"success": False, "error": f"Unknown signers: {', '.join(unknown)}"}
        )
    if amount <= 0:
        return jsonify({"success": False, "error": "Amount must be positive"})

    if script_type == "P2WSH":
        sp, ws_bytes = _p2wsh_multisig(m, signers)
        sh_hex = sha256(ws_bytes).hex()
        witness_scripts[sh_hex] = ws_bytes
        witness_script_info[sh_hex] = {"m": m, "n": len(signers), "signers": signers}
    else:  # P2SH
        sp, rs_bytes = _p2sh_multisig(m, signers)
        sh_hex = hash160(rs_bytes).hex()
        redeem_scripts[sh_hex] = rs_bytes
        multisig_info[sh_hex] = {"m": m, "n": len(signers), "signers": signers}

    fake_txid = sha256(bytes.fromhex(sh_hex) + os.urandom(4))
    utxo_set.add_coinbase(fake_txid, [TxOutput(amount, sp)])

    return jsonify(
        {
            "success": True,
            "description": f"{m}-of-{len(signers)} {script_type} ({', '.join(signers)})",
            "amount": amount,
        }
    )


@app.route("/api/transact", methods=["POST"])
def api_transact():
    """
    Body:
      inputs  : [{txid: "hex", vout: int}]
      outputs : [{recipient: "Alice"|"Bob"|"Charlie", amount: int,
                  script_type: "P2PKH"|"P2WPKH"|"P2SH",
                  // for P2SH outputs:
                  m: 2, multisig_signers: ["Alice","Bob"]}]
    """
    body = request.get_json(force=True)
    try:
        # ── Resolve inputs ────────────────────────────────────────────────
        tx_inputs, input_utxos = [], []
        for i, inp in enumerate(body.get("inputs", [])):
            txid = bytes.fromhex(inp["txid"])
            vout = int(inp["vout"])
            utxo = utxo_set.get(txid, vout)
            if utxo is None:
                return jsonify(
                    {"success": False, "error": f"Input {i}: UTXO not found"}
                )
            tx_inputs.append(TxInput(txid=txid, vout=vout))
            input_utxos.append(utxo)

        # ── Build outputs ─────────────────────────────────────────────────
        tx_outputs = []
        tx_output_metas = []  # parallel: multisig info dict or None per output

        for i, out in enumerate(body.get("outputs", [])):
            amount = int(out["amount"])
            script_type = out.get("script_type", "P2PKH")
            if amount <= 0:
                return jsonify(
                    {"success": False, "error": f"Output {i}: amount must be positive"}
                )

            if script_type in ("P2SH", "P2WSH"):
                # Multisig output
                out_m = int(out.get("m", 2))
                out_signers = out.get("multisig_signers", [])
                if len(out_signers) < 2:
                    return jsonify(
                        {
                            "success": False,
                            "error": f"Output {i}: {script_type} needs ≥2 signers",
                        }
                    )
                unknown = [s for s in out_signers if s not in ACCOUNTS]
                if unknown:
                    return jsonify(
                        {
                            "success": False,
                            "error": f"Output {i}: unknown signers {unknown}",
                        }
                    )
                ms_meta = {"m": out_m, "n": len(out_signers), "signers": out_signers}
                if script_type == "P2WSH":
                    sp, ws_bytes = _p2wsh_multisig(out_m, out_signers)
                    sh_hex = sha256(ws_bytes).hex()
                    witness_scripts[sh_hex] = ws_bytes
                    witness_script_info[sh_hex] = ms_meta
                else:  # P2SH
                    sp, rs_bytes = _p2sh_multisig(out_m, out_signers)
                    sh_hex = hash160(rs_bytes).hex()
                    redeem_scripts[sh_hex] = rs_bytes
                    multisig_info[sh_hex] = ms_meta
                tx_outputs.append(TxOutput(amount=amount, script_pubkey=sp))
                tx_output_metas.append(ms_meta)
            else:
                recipient = out.get("recipient", "")
                if recipient not in ACCOUNTS:
                    return jsonify(
                        {
                            "success": False,
                            "error": f"Output {i}: unknown recipient '{recipient}'",
                        }
                    )
                pk = bytes.fromhex(ACCOUNTS[recipient]["pubkey"])
                script = SCRIPT_FACTORIES.get(script_type, _p2pkh)(pk)
                tx_outputs.append(TxOutput(amount=amount, script_pubkey=script))
                tx_output_metas.append(None)

        if not tx_inputs:
            return jsonify({"success": False, "error": "No inputs provided"})
        if not tx_outputs:
            return jsonify({"success": False, "error": "No outputs provided"})

        tx = Transaction(inputs=tx_inputs, outputs=tx_outputs)

        # ── Sign each input ───────────────────────────────────────────────
        def _multisig_sigs(info: dict, sig_hash: bytes) -> list[bytes]:
            return [
                SigningKey.from_string(
                    ACCOUNTS[s]["privkey_int"].to_bytes(32, "big"), curve=SECP256k1
                ).sign_digest(sig_hash)
                + b"\x01"
                for s in info["signers"][: info["m"]]
            ]

        for i, (inp, utxo) in enumerate(zip(tx.inputs, input_utxos)):
            stype = _script_type(utxo.script_pubkey)

            if stype == "P2SH":
                sh = utxo.script_pubkey.cmds[1].hex()
                rs_bytes = redeem_scripts.get(sh)
                info = multisig_info.get(sh)
                if not rs_bytes or not info:
                    return jsonify(
                        {
                            "success": False,
                            "error": f"Input {i}: P2SH redeem script not registered",
                        }
                    )
                # legacy sighash for regular P2SH
                sh_hash = tx.sighash(i, utxo.script_pubkey)
                inp.script_sig = [b""] + _multisig_sigs(info, sh_hash) + [rs_bytes]

            elif stype == "P2WSH":
                sh = utxo.script_pubkey.cmds[1].hex()
                ws_bytes = witness_scripts.get(sh)
                info = witness_script_info.get(sh)
                if not ws_bytes or not info:
                    return jsonify(
                        {
                            "success": False,
                            "error": f"Input {i}: P2WSH witness script not registered",
                        }
                    )
                # BIP143: scriptCode = witnessScript
                bip143_hash = tx.sighash_segwit(i, ws_bytes, utxo.amount)
                inp.witness = [b""] + _multisig_sigs(info, bip143_hash) + [ws_bytes]

            elif stype == "P2WPKH":
                owner = _owner(utxo.script_pubkey)
                if owner not in ACCOUNTS:
                    return jsonify(
                        {
                            "success": False,
                            "error": f"Input {i}: cannot identify P2WPKH owner",
                        }
                    )
                sk = SigningKey.from_string(
                    ACCOUNTS[owner]["privkey_int"].to_bytes(32, "big"), curve=SECP256k1
                )
                pubkey = sk.get_verifying_key().to_string()
                # BIP143: scriptCode = P2PKH equivalent
                h = utxo.script_pubkey.cmds[1]  # 20-byte hash
                script_code = _bip143_script_code_p2wpkh(h)
                bip143_hash = tx.sighash_segwit(i, script_code, utxo.amount)
                inp.witness = [sk.sign_digest(bip143_hash) + b"\x01", pubkey]

            elif stype == "P2TR":
                owner = _owner(utxo.script_pubkey)
                if owner not in ACCOUNTS:
                    return jsonify(
                        {
                            "success": False,
                            "error": f"Input {i}: cannot identify P2TR owner",
                        }
                    )
                sk = SigningKey.from_string(
                    ACCOUNTS[owner]["privkey_int"].to_bytes(32, "big"), curve=SECP256k1
                )
                sh_hash = tx.sighash(i, utxo.script_pubkey)
                inp.witness = [sk.sign_digest(sh_hash) + b"\x01"]

            else:  # P2PKH / legacy
                owner = _owner(utxo.script_pubkey)
                if owner not in ACCOUNTS:
                    return jsonify(
                        {"success": False, "error": f"Input {i}: cannot identify owner"}
                    )
                sk = SigningKey.from_string(
                    ACCOUNTS[owner]["privkey_int"].to_bytes(32, "big"), curve=SECP256k1
                )
                pubkey = sk.get_verifying_key().to_string()
                sh_hash = tx.sighash(i, utxo.script_pubkey)
                inp.script_sig = [sk.sign_digest(sh_hash) + b"\x01", pubkey]

        # ── Collect replay + malleation data (after signing) ─────────────
        inputs_replay = []
        for i, (inp, utxo) in enumerate(zip(tx.inputs, input_utxos)):
            stype = _script_type(utxo.script_pubkey)
            if stype == "P2WPKH":
                h = utxo.script_pubkey.cmds[1]
                sc = _bip143_script_code_p2wpkh(h)
                used_hash = tx.sighash_segwit(i, sc, utxo.amount)
            elif stype == "P2WSH":
                ws = witness_scripts.get(utxo.script_pubkey.cmds[1].hex(), b"")
                used_hash = tx.sighash_segwit(i, ws, utxo.amount)
            else:
                used_hash = tx.sighash(i, utxo.script_pubkey)
            inputs_replay.append({
                "script_type":       stype,
                "script_pubkey_hex": utxo.script_pubkey.serialize().hex(),
                "script_sig_items":  [x.hex() for x in inp.script_sig],
                "witness_items":     [x.hex() for x in inp.witness],
                "sighash_hex":       used_hash.hex(),
            })

        # ── Validate & apply ──────────────────────────────────────────────
        ok, msg = utxo_set.validate_and_apply(tx)

        total_in = sum(u.amount for u in input_utxos)
        total_out = sum(o.amount for o in tx_outputs)

        def _out_record(o: TxOutput, meta: dict | None) -> dict:
            stype = _script_type(o.script_pubkey)
            d = {
                "amount": o.amount,
                "recipient": _owner(o.script_pubkey),
                "script_type": stype,
            }
            if meta:
                d["multisig"] = meta
            return d

        def _inp_label(u):
            stype = _script_type(u.script_pubkey)
            if stype == "P2SH":
                c = u.script_pubkey.cmds
                sh = c[1].hex() if isinstance(c[1], bytes) else ""
                info = multisig_info.get(sh, {})
                return (
                    f"{info.get('m','?')}-of-{info.get('n','?')} {stype} "
                    f"({', '.join(info.get('signers',[]))})"
                )
            if stype == "P2WSH":
                c = u.script_pubkey.cmds
                sh = c[1].hex() if isinstance(c[1], bytes) else ""
                info = witness_script_info.get(sh, {})
                return (
                    f"{info.get('m','?')}-of-{info.get('n','?')} P2WSH "
                    f"({', '.join(info.get('signers',[]))})"
                )
            return _owner(u.script_pubkey)

        record = {
            "txid": tx.txid.hex(),
            "txid_short": tx.txid.hex()[:16] + "…",
            "success": ok,
            "message": msg,
            "total_in": total_in,
            "total_out": total_out,
            "fee": total_in - total_out,
            "inputs": [
                {
                    "txid_short": u.txid.hex()[:8] + "…",
                    "vout": u.vout,
                    "amount": u.amount,
                    "owner": _inp_label(u),
                    "type": _script_type(u.script_pubkey),
                }
                for u in input_utxos
            ],
            "outputs":       [_out_record(o, m) for o, m in zip(tx_outputs, tx_output_metas)],
            "inputs_replay": inputs_replay,
            "raw_tx":        tx._serialize().hex(),
        }
        if ok:
            tx_history.append(record)
        return jsonify(record)

    except Exception as e:
        return jsonify(
            {"success": False, "error": str(e), "traceback": traceback.format_exc()}
        )


# ── Script replay helpers ─────────────────────────────────────────────────


def _fmt_bytes(item) -> dict:
    """Format a stack item for JSON (label, type, hex, short display)."""
    if not isinstance(item, bytes):
        return {"label": str(item), "type": "other", "hex": "", "short": str(item)}
    h, n = item.hex(), len(item)
    if n == 0:
        return {"label": "∅", "type": "dummy", "hex": h, "short": "∅"}
    if n == 1 and item[0] == 1:
        return {"label": "TRUE", "type": "bool_true", "hex": h, "short": "TRUE"}
    if n == 65 and item[-1] == 0x01:
        return {"label": "sig", "type": "sig", "hex": h, "short": h[:6] + "…" + h[-4:]}
    if n in (33, 65) and item[0] in (0x02, 0x03, 0x04):
        return {"label": "pubkey", "type": "pubkey", "hex": h, "short": h[:6] + "…" + h[-4:]}
    if n == 64:
        return {"label": "pubkey", "type": "pubkey", "hex": h, "short": h[:6] + "…" + h[-4:]}
    if n == 20:
        return {"label": "hash160", "type": "hash", "hex": h, "short": h[:6] + "…" + h[-4:]}
    if n == 32:
        return {"label": "hash256", "type": "hash", "hex": h, "short": h[:6] + "…" + h[-4:]}
    short = (h[:10] + "…") if len(h) > 10 else h
    return {"label": "data", "type": "data", "hex": h, "short": short}


def _fmt_instr(cmd) -> str:
    """Human-readable label for one instruction."""
    if isinstance(cmd, bytes):
        n = len(cmd)
        if n == 0:  return "PUSH ∅"
        if n == 65 and cmd[-1] == 0x01: return "PUSH <sig>"
        if n in (33, 65) and cmd[0] in (0x02, 0x03, 0x04): return "PUSH <pubkey>"
        if n == 64:  return "PUSH <pubkey>"
        if n == 20:  return "PUSH <hash160>"
        if n == 32:  return "PUSH <hash256>"
        return f"PUSH <{cmd.hex()[:8]}…>" if n > 4 else f"PUSH {cmd.hex()}"
    return opcode_2_op(cmd) or f"0x{cmd:02x}"


def _collect_vm_steps(vm) -> list:
    """Step through vm and return a snapshot list."""
    def snap():
        return {
            "pc":            vm.pc,
            "stack":         [_fmt_bytes(x) for x in vm.stack],
            "is_terminated": vm.is_terminated,
            "is_valid":      vm.is_valid() if vm.is_terminated else None,
        }
    steps = [snap()]
    for _ in range(500):
        if vm.is_terminated:
            break
        try:
            vm.step()
        except Exception as e:
            steps.append({**snap(), "is_terminated": True, "is_valid": False,
                          "error": str(e)})
            break
        steps.append(snap())
    return steps


@app.route("/api/replay", methods=["POST"])
def api_replay():
    """
    Step-by-step script execution replay for a stored transaction input.
    Uses BitcoinScriptInterpreterV2 which pre-computes the full instruction list.
    """
    body      = request.get_json(force=True)
    txid      = body.get("txid", "")
    input_idx = int(body.get("input_idx", 0))

    record = next((r for r in tx_history if r.get("txid") == txid), None)
    if not record or "inputs_replay" not in record:
        return jsonify({"error": "Replay data not available for this transaction"})

    ri = record["inputs_replay"]
    if input_idx >= len(ri):
        return jsonify({"error": f"Input index {input_idx} out of range"})

    d     = ri[input_idx]
    stype = d["script_type"]

    if stype not in ("P2PKH", "P2WPKH", "P2SH", "P2WSH"):
        return jsonify({"error": f"Replay not supported for {stype} inputs"})

    try:
        tx_hash     = bytes.fromhex(d["sighash_hex"])
        script_sig  = Script([bytes.fromhex(x) for x in d["script_sig_items"]])
        script_pub  = Script.parse_hex(d["script_pubkey_hex"])
        witness     = Script([bytes.fromhex(x) for x in d["witness_items"]])

        vm = BitcoinScriptInterpreterV2(tx_hash, script_sig, script_pub, witness)

        steps = _collect_vm_steps(vm)

        instructions = [
            {"name": _fmt_instr(cmd), "phase": itype.value}
            for cmd, itype in zip(vm.instructions, vm.instr_types)
        ]

        return jsonify({
            "script_type": stype,
            "trans_type":  vm.trans_type.value,
            "instructions": instructions,
            "steps":        steps,
        })
    except Exception as e:
        return jsonify({"error": str(e), "traceback": traceback.format_exc()})


@app.route("/api/malleate", methods=["POST"])
def api_malleate():
    """
    Demonstrate ECDSA signature malleability.
    P2PKH:  sig is in scriptSig → part of TXID → TXID changes when s → n-s
    P2WPKH: sig is in witness   → NOT in TXID  → TXID stays same (SegWit fix)
    """
    _N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    body      = request.get_json(force=True)
    txid      = body.get("txid", "")
    input_idx = int(body.get("input_idx", 0))

    record = next((r for r in tx_history if r.get("txid") == txid), None)
    if not record:
        return jsonify({"error": "Transaction not found in history"})

    ri = record.get("inputs_replay", [])
    if input_idx >= len(ri):
        return jsonify({"error": f"Input index {input_idx} out of range"})

    d     = ri[input_idx]
    stype = d["script_type"]

    if stype not in ("P2PKH", "P2WPKH"):
        return jsonify({"error":
            f"Malleation only applies to P2PKH / P2WPKH (got {stype})"})

    sig_pool     = d["script_sig_items"] if stype == "P2PKH" else d["witness_items"]
    orig_sig_hex = next(
        (x for x in sig_pool
         if len(bytes.fromhex(x)) == 65 and bytes.fromhex(x)[-1] == 0x01),
        None
    )
    if not orig_sig_hex:
        return jsonify({"error": "ECDSA signature not found in this input"})

    orig_sig = bytes.fromhex(orig_sig_hex)
    r        = int.from_bytes(orig_sig[:32],  "big")
    s        = int.from_bytes(orig_sig[32:64], "big")
    s_prime  = _N - s
    malleated_sig = r.to_bytes(32, "big") + s_prime.to_bytes(32, "big") + b"\x01"

    raw_tx = bytes.fromhex(record.get("raw_tx", ""))
    if not raw_tx:
        return jsonify({"error": "Raw transaction not stored — reset and retry"})

    if stype == "P2PKH":
        if orig_sig not in raw_tx:
            return jsonify({"error": "Signature bytes not found in raw transaction"})
        malleated_raw  = raw_tx.replace(orig_sig, malleated_sig, 1)
        malleated_txid = sha256(sha256(malleated_raw)).hex()
    else:
        malleated_txid = txid   # witness not in legacy serialization

    return jsonify({
        "script_type":    stype,
        "orig_txid":      txid,
        "malleated_txid": malleated_txid,
        "txid_changed":   malleated_txid != txid,
        "r":              r.to_bytes(32, "big").hex(),
        "s":              s.to_bytes(32, "big").hex(),
        "s_prime":        s_prime.to_bytes(32, "big").hex(),
        "N_hex":          hex(_N),
    })


if __name__ == "__main__":
    # port = int(os.environ.get("PORT", 5000))
    # debug = os.environ.get("FLASK_ENV") != "production"
    print("\n  Bitcoin UTXO Visualizer")
    print(f"  http://localhost:{5000}\n")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
