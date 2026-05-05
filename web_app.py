"""
Bitcoin UTXO Visualizer — Flask backend

Run:  python web_app.py
Then open http://localhost:5000
"""
import os
import sys
import traceback
sys.path.insert(0, "src")

from flask import Flask, jsonify, request, render_template

from utxo import UTXOSet, TxInput, TxOutput, Transaction, UTXO, _compute_sighash
from script import Script
from crypto import hash160, sha256, sign_schnorr, sign_schnorr_musig, aggregate_pubkeys
from ecdsa import SigningKey, SECP256k1

app = Flask(__name__)

# ── Pre-loaded accounts ───────────────────────────────────────────────────

def _make_account(privkey_int: int):
    sk = SigningKey.from_string(privkey_int.to_bytes(32, "big"), curve=SECP256k1)
    vk = sk.get_verifying_key()
    pk = vk.to_string()          # 64-byte x||y (no prefix)
    ph = hash160(pk)
    xonly = pk[:32]              # x-coordinate = x-only pubkey for P2TR (BIP340)
    return {
        "privkey_int":  privkey_int,
        "pubkey":       pk.hex(),
        "pubkey_hash":  ph.hex(),
        "address":      ph.hex()[:12] + "…",
        "xonly_pubkey": xonly.hex(),
    }

ACCOUNTS = {
    "Alice":   _make_account(1),
    "Bob":     _make_account(2),
    "Charlie": _make_account(3),
}

OWNER_COLORS = {"Alice": "primary", "Bob": "success", "Charlie": "warning"}


# ── Script factories ──────────────────────────────────────────────────────

def _p2pkh(pubkey: bytes) -> Script:
    h = hash160(pubkey)
    return Script.parse(
        f"OP_DUP OP_HASH160 <{h.hex()}> OP_EQUALVERIFY OP_CHECKSIG"
    )

def _p2wpkh(pubkey: bytes) -> Script:
    return Script.parse(f"OP_0 <{hash160(pubkey).hex()}>")

def _multisig_redeem(m: int, signers: list[str]) -> bytes:
    """Serialize the bare M-of-N multisig script."""
    pubkeys  = [bytes.fromhex(ACCOUNTS[s]["pubkey"]) for s in signers]
    n        = len(signers)
    pk_items = " ".join(f"<{pk.hex()}>" for pk in pubkeys)
    return Script.parse(f"OP_{m} {pk_items} OP_{n} OP_CHECKMULTISIG").serialize()

def _p2sh_multisig(m: int, signers: list[str]) -> tuple[Script, bytes]:
    """Return (scriptPubKey, redeem_script_bytes) for P2SH M-of-N multisig."""
    rs_bytes = _multisig_redeem(m, signers)
    sh       = hash160(rs_bytes)
    sp       = Script.parse(f"OP_HASH160 <{sh.hex()}> OP_EQUAL")
    return sp, rs_bytes

def _p2wsh_multisig(m: int, signers: list[str]) -> tuple[Script, bytes]:
    """Return (scriptPubKey, witness_script_bytes) for P2WSH M-of-N multisig."""
    ws_bytes = _multisig_redeem(m, signers)
    sh       = sha256(ws_bytes)
    sp       = Script.parse(f"OP_0 <{sh.hex()}>")
    return sp, ws_bytes

def _p2tr_script(xonly_pubkey: bytes) -> Script:
    """P2TR scriptPubKey: OP_1 <32-byte-x-only-pubkey> (BIP341)."""
    return Script.parse(f"OP_1 <{xonly_pubkey.hex()}>")

def _bip143_script_code_p2wpkh(pubkey_hash: bytes) -> bytes:
    """BIP143 scriptCode for P2WPKH: the equivalent P2PKH script."""
    return bytes([0x76, 0xa9, 0x14]) + pubkey_hash + bytes([0x88, 0xac])

SCRIPT_FACTORIES = {"P2PKH": _p2pkh, "P2WPKH": _p2wpkh}


# ── Script replay helpers ─────────────────────────────────────────────────

def _fmt_stack_item(item) -> dict:
    """Format one stack item for JSON (label, hex, short display, type)."""
    if not isinstance(item, bytes):
        return {"label": str(item), "hex": "", "short": str(item), "type": "other"}
    h, n = item.hex(), len(item)
    if n == 0:
        return {"label": "OP_0", "hex": "", "short": "∅", "type": "dummy"}
    if n == 1 and item[0] == 1:
        return {"label": "TRUE",  "hex": h, "short": "TRUE",  "type": "bool_true"}
    # Raw ECDSA sig: r(32) ‖ s(32) ‖ SIGHASH_ALL(1) = 65 bytes, last byte 0x01
    if n == 65 and item[-1] == 0x01:
        return {"label": "sig",    "hex": h, "short": h[:6] + "…" + h[-4:], "type": "sig"}
    if n == 64:
        return {"label": "pubkey", "hex": h, "short": h[:6] + "…" + h[-4:], "type": "pubkey"}
    if n in (33, 65) and item[0] in (0x02, 0x03, 0x04):
        return {"label": "pubkey", "hex": h, "short": h[:6] + "…" + h[-4:], "type": "pubkey"}
    if n == 20:
        return {"label": "hash160","hex": h, "short": h[:6] + "…" + h[-4:], "type": "hash"}
    if n == 32:
        return {"label": "hash256","hex": h, "short": h[:6] + "…" + h[-4:], "type": "hash"}
    return {"label": "data", "hex": h, "short": (h[:10] + "…") if len(h) > 10 else h, "type": "data"}


def _cmd_label(cmd) -> str:
    """Return human-readable operation name for a script command."""
    from opcodes import opcode_2_op
    if isinstance(cmd, bytes):
        n = len(cmd)
        if n == 0:          return "PUSH ∅ (OP_0 / dummy)"
        if n == 65 and cmd[-1] == 0x01:                     return "PUSH <sig>"
        if n == 64:         return "PUSH <pubkey>"
        if n in (33, 65) and cmd[0] in (0x02, 0x03, 0x04): return "PUSH <pubkey>"
        if n == 20:         return "PUSH <hash160>"
        if n == 32:         return "PUSH <hash256>"
        return f"PUSH <{cmd.hex()[:8]}…>"
    name = opcode_2_op(cmd)
    return name or f"OP_{hex(cmd)}"


def _replay_steps(utxo_script_hex: str, script_sig_hexes: list,
                  witness_hexes: list, sighash_hex: str) -> list:
    """
    Run the Bitcoin script VM step-by-step and return a trace list.
    Each entry: {op, stack, phase, [error], [valid]}
    """
    from script import Script
    from engine import BitcoinScriptInterpreter

    sp   = Script.parse_hex(utxo_script_hex)
    init = [bytes.fromhex(x) for x in script_sig_hexes] or None
    wit  = [bytes.fromhex(x) for x in witness_hexes]    or None
    sh   = bytes.fromhex(sighash_hex)

    vm = BitcoinScriptInterpreter(script=sp, initial_stack=init, witness=wit, tx_sig_hash=sh)

    def cur():  return vm.active_inner_vm if vm.active_inner_vm else vm
    def snap(): return [_fmt_stack_item(x) for x in cur().stack]
    def next_op():
        avm = cur()
        if avm.pc >= len(avm.script.cmds): return "—"
        return _cmd_label(avm.script.cmds[avm.pc])

    steps = [{"op": "START", "stack": snap(), "phase": "init"}]

    for _ in range(300):
        if vm.terminated:
            break
        had_inner = vm.active_inner_vm is not None

        # Annotate special transitions before the step executes
        if not had_inner and vm.pc == 0 and vm._is_witness_program():
            if vm.script.cmds[0] == 0x51:
                op = "P2TR: verify Schnorr signature"
            else:
                op = "SegWit detected → inner VM"
        else:
            op = next_op()

        try:
            vm.step()
        except Exception as e:
            steps.append({"op": op, "stack": snap(), "phase": "error", "error": str(e)})
            break

        now_inner = vm.active_inner_vm is not None
        if   not had_inner and now_inner: phase = "inner_start"
        elif now_inner:                   phase = "inner"
        else:                             phase = "outer"

        steps.append({"op": op, "stack": snap(), "phase": phase})

    steps.append({
        "op":    "✅ VALID" if vm._is_valid() else "❌ INVALID",
        "stack": [_fmt_stack_item(x) for x in vm.stack],
        "phase": "result",
        "valid": vm._is_valid(),
    })
    return steps


# ── Script metadata helpers ───────────────────────────────────────────────

def _script_type(sp: Script) -> str:
    c = sp.cmds
    if len(c) == 5 and c[0] == 0x76:
        return "P2PKH"
    if len(c) == 2 and (c[0] == 0x00 or c[0] == b'\x00') and isinstance(c[1], bytes):
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
    if len(c) == 2 and (c[0] == 0x00 or c[0] == b'\x00') and isinstance(c[1], bytes) and len(c[1]) == 32:
        sh = c[1].hex()
        if sh in witness_script_info:
            return witness_script_info[sh]["signers"][0]
        return "P2WSH"
    # P2TR — match x-only pubkey (single-key) or aggregate key (MuSig)
    if len(c) == 2 and c[0] == 0x51 and isinstance(c[1], bytes) and len(c[1]) == 32:
        xonly = c[1].hex()
        for name, acct in ACCOUNTS.items():
            if acct["xonly_pubkey"] == xonly:
                return name
        if xonly in p2tr_musig_info:
            return p2tr_musig_info[xonly]["signers"][0]
        return "P2TR"
    # P2PKH / P2WPKH — match pubkey hash
    h = None
    if len(c) == 5 and c[0] == 0x76 and isinstance(c[2], bytes):
        h = c[2].hex()
    elif len(c) == 2 and (c[0] == 0x00 or c[0] == b'\x00') and isinstance(c[1], bytes) and len(c[1]) == 20:
        h = c[1].hex()
    if h:
        for name, acct in ACCOUNTS.items():
            if acct["pubkey_hash"] == h:
                return name
    return "Unknown"

def _utxo_dict(u: UTXO) -> dict:
    stype = _script_type(u.script_pubkey)
    d = {
        "txid":        u.txid.hex(),
        "txid_short":  u.txid.hex()[:10] + "…",
        "vout":        u.vout,
        "amount":      u.amount,
        "script_type": stype,
        "owner":       _owner(u.script_pubkey),
    }
    # Attach multisig metadata so the frontend can render co-owner badges
    if stype == "P2SH":
        c = u.script_pubkey.cmds
        if len(c) == 3 and isinstance(c[1], bytes):
            sh = c[1].hex()
            if sh in multisig_info:
                d["multisig"] = multisig_info[sh]   # {m, n, signers[, subtype]}
    elif stype == "P2WSH":
        c = u.script_pubkey.cmds
        if len(c) == 2 and isinstance(c[1], bytes):
            sh = c[1].hex()
            if sh in witness_script_info:
                d["multisig"] = witness_script_info[sh]
    elif stype == "P2TR":
        c = u.script_pubkey.cmds
        if len(c) == 2 and isinstance(c[1], bytes):
            agg_hex = c[1].hex()
            if agg_hex in p2tr_musig_info:
                d["multisig"] = p2tr_musig_info[agg_hex]
    return d


# ── Global state ──────────────────────────────────────────────────────────

utxo_set:            UTXOSet       = UTXOSet()
tx_history:          list          = []
redeem_scripts:      dict[str, bytes] = {}   # hash160_hex → redeem_script_bytes  (P2SH)
multisig_info:       dict[str, dict]  = {}   # hash160_hex → {m, n, signers}       (P2SH)
witness_scripts:     dict[str, bytes] = {}   # sha256_hex  → witness_script_bytes  (P2WSH)
witness_script_info: dict[str, dict]  = {}   # sha256_hex  → {m, n, signers}       (P2WSH)
p2tr_musig_info:     dict[str, dict]  = {}   # xonly_agg_hex → {m, n, signers}     (P2TR MuSig)

GENESIS_TXID = b"\x00" * 32

def _seed():
    global utxo_set, tx_history, redeem_scripts, multisig_info
    global witness_scripts, witness_script_info, p2tr_musig_info
    utxo_set             = UTXOSet()
    tx_history           = []
    redeem_scripts       = {}
    multisig_info        = {}
    witness_scripts      = {}
    witness_script_info  = {}
    p2tr_musig_info      = {}
    alice_pk      = bytes.fromhex(ACCOUNTS["Alice"]["pubkey"])
    bob_pk        = bytes.fromhex(ACCOUNTS["Bob"]["pubkey"])
    charlie_pk    = bytes.fromhex(ACCOUNTS["Charlie"]["pubkey"])
    alice_xonly   = bytes.fromhex(ACCOUNTS["Alice"]["xonly_pubkey"])
    bob_xonly     = bytes.fromhex(ACCOUNTS["Bob"]["xonly_pubkey"])
    charlie_xonly = bytes.fromhex(ACCOUNTS["Charlie"]["xonly_pubkey"])
    utxo_set.add_coinbase(GENESIS_TXID, [
        TxOutput(100_000, _p2pkh(alice_pk)),
        TxOutput(75_000,  _p2wpkh(bob_pk)),
        TxOutput(50_000,  _p2pkh(charlie_pk)),
        TxOutput(60_000,  _p2tr_script(alice_xonly)),
        TxOutput(45_000,  _p2tr_script(bob_xonly)),
        TxOutput(30_000,  _p2tr_script(charlie_xonly)),
    ])

_seed()


# ── Routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", accounts=ACCOUNTS, owner_colors=OWNER_COLORS)


@app.route("/api/state")
def api_state():
    all_u = utxo_set.all_utxos()
    return jsonify({
        "utxos":      [_utxo_dict(u) for u in all_u],
        "total":      sum(u.amount for u in all_u),
        "utxo_count": len(all_u),
        "tx_count":   len(tx_history),
    })


@app.route("/api/history")
def api_history():
    # Strip large inputs_replay from list response; replay fetched on demand
    slim = [{k: v for k, v in r.items() if k != "inputs_replay"}
            for r in tx_history[-30:]]
    return jsonify({"history": slim})


@app.route("/api/replay", methods=["POST"])
def api_replay():
    body      = request.get_json(force=True)
    txid      = body.get("txid", "")
    input_idx = int(body.get("input_idx", 0))

    record = next((r for r in tx_history if r.get("txid") == txid), None)
    if not record or "inputs_replay" not in record:
        return jsonify({"error": "Replay data not available for this transaction"})

    ri = record["inputs_replay"]
    if input_idx >= len(ri):
        return jsonify({"error": f"Input index {input_idx} out of range"})

    d = ri[input_idx]
    try:
        steps = _replay_steps(d["utxo_script"], d["script_sig"], d["witness"], d["sighash"])
    except Exception as e:
        return jsonify({"error": str(e), "traceback": traceback.format_exc()})

    return jsonify({"script_type": d["script_type"], "steps": steps})


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
    body        = request.get_json(force=True)
    m           = int(body.get("m", 2))
    signers     = body.get("signers", [])
    amount      = int(body.get("amount", 100_000))
    script_type = body.get("script_type", "P2SH")

    if len(signers) < 2:
        return jsonify({"success": False,
                        "error": "Multisig requires at least 2 signers"})
    if not 1 <= m <= len(signers):
        return jsonify({"success": False,
                        "error": f"Invalid threshold: {m}-of-{len(signers)}"})
    unknown = [s for s in signers if s not in ACCOUNTS]
    if unknown:
        return jsonify({"success": False,
                        "error": f"Unknown signers: {', '.join(unknown)}"})
    if amount <= 0:
        return jsonify({"success": False, "error": "Amount must be positive"})

    if script_type == "P2TR-MuSig":
        # MuSig n-of-n: aggregate all signers' x-only pubkeys into a single key
        n_signers = len(signers)
        xonly_pks = [bytes.fromhex(ACCOUNTS[s]["xonly_pubkey"]) for s in signers]
        agg_xonly = aggregate_pubkeys(xonly_pks)
        agg_hex   = agg_xonly.hex()
        sp        = _p2tr_script(agg_xonly)
        p2tr_musig_info[agg_hex] = {"m": n_signers, "n": n_signers, "signers": signers}
        fake_txid = sha256(bytes.fromhex(agg_hex) + os.urandom(4))
        desc      = f"{n_signers}-of-{n_signers} P2TR MuSig ({', '.join(signers)})"
    elif script_type == "P2WSH":
        sp, ws_bytes = _p2wsh_multisig(m, signers)
        agg_hex = sha256(ws_bytes).hex()
        witness_scripts[agg_hex]     = ws_bytes
        witness_script_info[agg_hex] = {"m": m, "n": len(signers), "signers": signers}
        fake_txid = sha256(bytes.fromhex(agg_hex) + os.urandom(4))
        desc      = f"{m}-of-{len(signers)} {script_type} ({', '.join(signers)})"
    else:  # P2SH
        sp, rs_bytes = _p2sh_multisig(m, signers)
        agg_hex = hash160(rs_bytes).hex()
        redeem_scripts[agg_hex] = rs_bytes
        multisig_info[agg_hex]  = {"m": m, "n": len(signers), "signers": signers}
        fake_txid = sha256(bytes.fromhex(agg_hex) + os.urandom(4))
        desc      = f"{m}-of-{len(signers)} {script_type} ({', '.join(signers)})"

    utxo_set.add_coinbase(fake_txid, [TxOutput(amount, sp)])

    return jsonify({
        "success":     True,
        "description": desc,
        "amount":      amount,
    })


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
                return jsonify({"success": False,
                                "error": f"Input {i}: UTXO not found"})
            tx_inputs.append(TxInput(txid=txid, vout=vout))
            input_utxos.append(utxo)

        # ── Build outputs ─────────────────────────────────────────────────
        tx_outputs      = []
        tx_output_metas = []   # parallel: multisig info dict or None per output

        for i, out in enumerate(body.get("outputs", [])):
            amount      = int(out["amount"])
            script_type = out.get("script_type", "P2PKH")
            if amount <= 0:
                return jsonify({"success": False,
                                "error": f"Output {i}: amount must be positive"})

            if script_type in ("P2SH", "P2WSH", "P2TR-MuSig"):
                # Multisig output
                out_m       = int(out.get("m", 2))
                out_signers = out.get("multisig_signers", [])
                if len(out_signers) < 2:
                    return jsonify({"success": False,
                                    "error": f"Output {i}: {script_type} needs ≥2 signers"})
                unknown = [s for s in out_signers if s not in ACCOUNTS]
                if unknown:
                    return jsonify({"success": False,
                                    "error": f"Output {i}: unknown signers {unknown}"})
                if script_type == "P2TR-MuSig":
                    # n-of-n MuSig: aggregate xonly pubkeys into one key
                    n_out = len(out_signers)
                    xonly_pks  = [bytes.fromhex(ACCOUNTS[s]["xonly_pubkey"]) for s in out_signers]
                    agg_xonly  = aggregate_pubkeys(xonly_pks)
                    agg_hex    = agg_xonly.hex()
                    sp         = _p2tr_script(agg_xonly)
                    ms_meta    = {"m": n_out, "n": n_out, "signers": out_signers}
                    p2tr_musig_info[agg_hex] = ms_meta
                elif script_type == "P2WSH":
                    ms_meta = {"m": out_m, "n": len(out_signers), "signers": out_signers}
                    sp, ws_bytes = _p2wsh_multisig(out_m, out_signers)
                    sh_hex = sha256(ws_bytes).hex()
                    witness_scripts[sh_hex]     = ws_bytes
                    witness_script_info[sh_hex] = ms_meta
                else:  # P2SH
                    ms_meta = {"m": out_m, "n": len(out_signers), "signers": out_signers}
                    sp, rs_bytes = _p2sh_multisig(out_m, out_signers)
                    sh_hex = hash160(rs_bytes).hex()
                    redeem_scripts[sh_hex] = rs_bytes
                    multisig_info[sh_hex]  = ms_meta
                tx_outputs.append(TxOutput(amount=amount, script_pubkey=sp))
                tx_output_metas.append(ms_meta)
            elif script_type == "P2TR":
                recipient = out.get("recipient", "")
                if recipient not in ACCOUNTS:
                    return jsonify({"success": False,
                                    "error": f"Output {i}: unknown recipient '{recipient}'"})
                xonly  = bytes.fromhex(ACCOUNTS[recipient]["xonly_pubkey"])
                script = _p2tr_script(xonly)
                tx_outputs.append(TxOutput(amount=amount, script_pubkey=script))
                tx_output_metas.append(None)
            else:
                recipient = out.get("recipient", "")
                if recipient not in ACCOUNTS:
                    return jsonify({"success": False,
                                    "error": f"Output {i}: unknown recipient '{recipient}'"})
                pk     = bytes.fromhex(ACCOUNTS[recipient]["pubkey"])
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
                ).sign_digest(sig_hash) + b"\x01"
                for s in info["signers"][: info["m"]]
            ]

        for i, (inp, utxo) in enumerate(zip(tx.inputs, input_utxos)):
            stype = _script_type(utxo.script_pubkey)

            if stype == "P2SH":
                sh       = utxo.script_pubkey.cmds[1].hex()
                rs_bytes = redeem_scripts.get(sh)
                info     = multisig_info.get(sh)
                if not rs_bytes or not info:
                    return jsonify({"success": False,
                                    "error": f"Input {i}: P2SH redeem script not registered"})
                # legacy sighash for regular P2SH
                sh_hash  = tx.sighash(i, utxo.script_pubkey)
                inp.script_sig = [b""] + _multisig_sigs(info, sh_hash) + [rs_bytes]

            elif stype == "P2WSH":
                sh       = utxo.script_pubkey.cmds[1].hex()
                ws_bytes = witness_scripts.get(sh)
                info     = witness_script_info.get(sh)
                if not ws_bytes or not info:
                    return jsonify({"success": False,
                                    "error": f"Input {i}: P2WSH witness script not registered"})
                # BIP143: scriptCode = witnessScript
                bip143_hash = tx.sighash_segwit(i, ws_bytes, utxo.amount)
                inp.witness = [b""] + _multisig_sigs(info, bip143_hash) + [ws_bytes]

            elif stype == "P2WPKH":
                owner = _owner(utxo.script_pubkey)
                if owner not in ACCOUNTS:
                    return jsonify({"success": False,
                                    "error": f"Input {i}: cannot identify P2WPKH owner"})
                sk     = SigningKey.from_string(
                             ACCOUNTS[owner]["privkey_int"].to_bytes(32, "big"),
                             curve=SECP256k1)
                pubkey = sk.get_verifying_key().to_string()
                # BIP143: scriptCode = P2PKH equivalent
                h           = utxo.script_pubkey.cmds[1]   # 20-byte hash
                script_code = _bip143_script_code_p2wpkh(h)
                bip143_hash = tx.sighash_segwit(i, script_code, utxo.amount)
                inp.witness = [sk.sign_digest(bip143_hash) + b"\x01", pubkey]

            elif stype == "P2TR":
                agg_hex = utxo.script_pubkey.cmds[1].hex()
                sh_hash = tx.sighash(i, utxo.script_pubkey)
                if agg_hex in p2tr_musig_info:
                    # MuSig n-of-n: combine all signers' keys and sign
                    info     = p2tr_musig_info[agg_hex]
                    privkeys = [ACCOUNTS[s]["privkey_int"] for s in info["signers"]]
                    xonly_pks= [bytes.fromhex(ACCOUNTS[s]["xonly_pubkey"]) for s in info["signers"]]
                    inp.witness = [sign_schnorr_musig(privkeys, xonly_pks, sh_hash)]
                else:
                    # Single-key P2TR
                    owner = _owner(utxo.script_pubkey)
                    if owner not in ACCOUNTS:
                        return jsonify({"success": False,
                                        "error": f"Input {i}: cannot identify P2TR owner"})
                    inp.witness = [sign_schnorr(ACCOUNTS[owner]["privkey_int"], sh_hash)]

            else:   # P2PKH / legacy
                owner = _owner(utxo.script_pubkey)
                if owner not in ACCOUNTS:
                    return jsonify({"success": False,
                                    "error": f"Input {i}: cannot identify owner"})
                sk      = SigningKey.from_string(
                              ACCOUNTS[owner]["privkey_int"].to_bytes(32, "big"),
                              curve=SECP256k1)
                pubkey  = sk.get_verifying_key().to_string()
                sh_hash = tx.sighash(i, utxo.script_pubkey)
                inp.script_sig = [sk.sign_digest(sh_hash) + b"\x01", pubkey]

        # ── Collect replay data (signed inputs + sighash) ────────────────
        inputs_replay = []
        for i, (inp, utxo) in enumerate(zip(tx.inputs, input_utxos)):
            inputs_replay.append({
                "script_type": _script_type(utxo.script_pubkey),
                "utxo_script": utxo.script_pubkey.serialize().hex(),
                "script_sig":  [x.hex() for x in inp.script_sig],
                "witness":     [x.hex() for x in inp.witness],
                "sighash":     _compute_sighash(tx, i, inp, utxo).hex(),
            })

        # ── Validate & apply ──────────────────────────────────────────────
        ok, msg = utxo_set.validate_and_apply(tx)

        total_in  = sum(u.amount for u in input_utxos)
        total_out = sum(o.amount for o in tx_outputs)

        def _out_record(o: TxOutput, meta: dict | None) -> dict:
            stype = _script_type(o.script_pubkey)
            d = {"amount": o.amount, "recipient": _owner(o.script_pubkey),
                 "script_type": stype}
            if meta:
                d["multisig"] = meta
            return d

        def _inp_label(u):
            stype = _script_type(u.script_pubkey)
            if stype == "P2SH":
                c    = u.script_pubkey.cmds
                sh   = c[1].hex() if isinstance(c[1], bytes) else ""
                info = multisig_info.get(sh, {})
                return (f"{info.get('m','?')}-of-{info.get('n','?')} {stype} "
                        f"({', '.join(info.get('signers',[]))})")
            if stype == "P2WSH":
                c    = u.script_pubkey.cmds
                sh   = c[1].hex() if isinstance(c[1], bytes) else ""
                info = witness_script_info.get(sh, {})
                return (f"{info.get('m','?')}-of-{info.get('n','?')} P2WSH "
                        f"({', '.join(info.get('signers',[]))})")
            if stype == "P2TR":
                c       = u.script_pubkey.cmds
                agg_hex = c[1].hex() if isinstance(c[1], bytes) else ""
                info    = p2tr_musig_info.get(agg_hex)
                if info:
                    n = info["n"]
                    return f"{n}-of-{n} P2TR MuSig ({', '.join(info['signers'])})"
            return _owner(u.script_pubkey)

        record = {
            "txid":       tx.txid.hex(),
            "txid_short": tx.txid.hex()[:16] + "…",
            "success":    ok,
            "message":    msg,
            "total_in":   total_in,
            "total_out":  total_out,
            "fee":        total_in - total_out,
            "inputs": [
                {"txid_short": u.txid.hex()[:8] + "…",
                 "vout":       u.vout,
                 "amount":     u.amount,
                 "owner":      _inp_label(u),
                 "type":       _script_type(u.script_pubkey)}
                for u in input_utxos
            ],
            "outputs":       [_out_record(o, m) for o, m in zip(tx_outputs, tx_output_metas)],
            "inputs_replay": inputs_replay,
            "raw_tx":        tx._serialize().hex(),  # legacy serialization for TXID / malleation demo
        }
        if ok:
            tx_history.append(record)
        return jsonify(record)

    except Exception as e:
        return jsonify({"success": False,
                        "error": str(e),
                        "traceback": traceback.format_exc()})


@app.route("/api/malleate", methods=["POST"])
def api_malleate():
    """
    Demonstrate ECDSA transaction malleability.

    For P2PKH:  the ECDSA sig lives in scriptSig, which IS part of the legacy
                serialization used to compute the TXID. Flipping s → n−s produces
                a different TXID — the attack changes the transaction's identity.

    For P2WPKH: the sig lives in the witness, which is NOT in the legacy serialization.
                Flipping s → n−s leaves the TXID unchanged (SegWit's fix).
    """
    # secp256k1 group order (constant)
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
            f"Malleation only applies to ECDSA-signed inputs (P2PKH / P2WPKH), not {stype}"})

    # Locate the ECDSA sig: r(32) ‖ s(32) ‖ SIGHASH_ALL(0x01) = 65 bytes
    sig_pool     = d["script_sig"] if stype == "P2PKH" else d["witness"]
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
    s_prime  = _N - s                        # the malleated s value

    malleated_sig = r.to_bytes(32, "big") + s_prime.to_bytes(32, "big") + b"\x01"

    raw_tx = bytes.fromhex(record.get("raw_tx", ""))
    if not raw_tx:
        return jsonify({"error": "Raw transaction not stored — reset and retry"})

    if stype == "P2PKH":
        # Sig is serialized inside scriptSig → inside the raw tx → affects TXID
        if orig_sig not in raw_tx:
            return jsonify({"error": "Could not locate signature bytes in raw transaction"})
        malleated_raw  = raw_tx.replace(orig_sig, malleated_sig, 1)
        malleated_txid = sha256(sha256(malleated_raw)).hex()
    else:
        # P2WPKH witness is segregated from the legacy serialization → TXID unchanged
        malleated_txid = txid

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
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    print("\n  Bitcoin UTXO Visualizer")
    print(f"  http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)
