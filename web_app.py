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

from utxo import UTXOSet, TxInput, TxOutput, Transaction, UTXO
from script import Script
from crypto import hash160, sha256
from ecdsa import SigningKey, SECP256k1

app = Flask(__name__)

# ── Pre-loaded accounts ───────────────────────────────────────────────────

def _make_account(privkey_int: int):
    sk = SigningKey.from_string(privkey_int.to_bytes(32, "big"), curve=SECP256k1)
    pk = sk.get_verifying_key().to_string()
    ph = hash160(pk)
    return {
        "privkey_int": privkey_int,
        "pubkey":      pk.hex(),
        "pubkey_hash": ph.hex(),
        "address":     ph.hex()[:12] + "…",
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

SCRIPT_FACTORIES = {"P2PKH": _p2pkh, "P2WPKH": _p2wpkh}


# ── Script metadata helpers ───────────────────────────────────────────────

def _script_type(sp: Script) -> str:
    c = sp.cmds
    if len(c) == 5 and c[0] == 0x76:                              return "P2PKH"
    if len(c) == 2 and c[0] == 0x00 and isinstance(c[1], bytes):
        return "P2WPKH" if len(c[1]) == 20 else "P2WSH"
    if len(c) == 2 and c[0] == 0x51:                              return "P2TR"
    if len(c) == 3 and c[0] == 0xA9:                              return "P2SH"
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
                d["multisig"] = multisig_info[sh]   # {m, n, signers}
    elif stype == "P2WSH":
        c = u.script_pubkey.cmds
        if len(c) == 2 and isinstance(c[1], bytes):
            sh = c[1].hex()
            if sh in witness_script_info:
                d["multisig"] = witness_script_info[sh]
    return d


# ── Global state ──────────────────────────────────────────────────────────

utxo_set:            UTXOSet       = UTXOSet()
tx_history:          list          = []
redeem_scripts:      dict[str, bytes] = {}   # hash160_hex → redeem_script_bytes  (P2SH)
multisig_info:       dict[str, dict]  = {}   # hash160_hex → {m, n, signers}       (P2SH)
witness_scripts:     dict[str, bytes] = {}   # sha256_hex  → witness_script_bytes  (P2WSH)
witness_script_info: dict[str, dict]  = {}   # sha256_hex  → {m, n, signers}       (P2WSH)

GENESIS_TXID = b"\x00" * 32

def _seed():
    global utxo_set, tx_history, redeem_scripts, multisig_info
    global witness_scripts, witness_script_info
    utxo_set             = UTXOSet()
    tx_history           = []
    redeem_scripts       = {}
    multisig_info        = {}
    witness_scripts      = {}
    witness_script_info  = {}
    alice_pk   = bytes.fromhex(ACCOUNTS["Alice"]["pubkey"])
    bob_pk     = bytes.fromhex(ACCOUNTS["Bob"]["pubkey"])
    charlie_pk = bytes.fromhex(ACCOUNTS["Charlie"]["pubkey"])
    utxo_set.add_coinbase(GENESIS_TXID, [
        TxOutput(100_000, _p2pkh(alice_pk)),
        TxOutput(75_000,  _p2wpkh(bob_pk)),
        TxOutput(50_000,  _p2pkh(charlie_pk)),
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
    return jsonify({"history": tx_history[-30:]})


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

    if script_type == "P2WSH":
        sp, ws_bytes = _p2wsh_multisig(m, signers)
        sh_hex = sha256(ws_bytes).hex()
        witness_scripts[sh_hex]     = ws_bytes
        witness_script_info[sh_hex] = {"m": m, "n": len(signers), "signers": signers}
    else:
        sp, rs_bytes = _p2sh_multisig(m, signers)
        sh_hex = hash160(rs_bytes).hex()
        redeem_scripts[sh_hex] = rs_bytes
        multisig_info[sh_hex]  = {"m": m, "n": len(signers), "signers": signers}

    fake_txid = sha256(bytes.fromhex(sh_hex) + os.urandom(4))
    utxo_set.add_coinbase(fake_txid, [TxOutput(amount, sp)])

    return jsonify({
        "success":     True,
        "description": f"{m}-of-{len(signers)} {script_type} ({', '.join(signers)})",
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
        tx_outputs = []
        for i, out in enumerate(body.get("outputs", [])):
            amount      = int(out["amount"])
            script_type = out.get("script_type", "P2PKH")
            if amount <= 0:
                return jsonify({"success": False,
                                "error": f"Output {i}: amount must be positive"})

            if script_type in ("P2SH", "P2WSH"):
                # Multisig output (P2SH or P2WSH)
                out_m       = int(out.get("m", 2))
                out_signers = out.get("multisig_signers", [])
                if len(out_signers) < 2:
                    return jsonify({"success": False,
                                    "error": f"Output {i}: {script_type} needs ≥2 signers"})
                unknown = [s for s in out_signers if s not in ACCOUNTS]
                if unknown:
                    return jsonify({"success": False,
                                    "error": f"Output {i}: unknown signers {unknown}"})
                if script_type == "P2WSH":
                    sp, ws_bytes = _p2wsh_multisig(out_m, out_signers)
                    sh_hex = sha256(ws_bytes).hex()
                    witness_scripts[sh_hex]     = ws_bytes
                    witness_script_info[sh_hex] = {
                        "m": out_m, "n": len(out_signers), "signers": out_signers
                    }
                else:
                    sp, rs_bytes = _p2sh_multisig(out_m, out_signers)
                    sh_hex = hash160(rs_bytes).hex()
                    redeem_scripts[sh_hex] = rs_bytes
                    multisig_info[sh_hex]  = {
                        "m": out_m, "n": len(out_signers), "signers": out_signers
                    }
                tx_outputs.append(TxOutput(amount=amount, script_pubkey=sp))
            else:
                recipient = out.get("recipient", "")
                if recipient not in ACCOUNTS:
                    return jsonify({"success": False,
                                    "error": f"Output {i}: unknown recipient '{recipient}'"})
                pk     = bytes.fromhex(ACCOUNTS[recipient]["pubkey"])
                script = SCRIPT_FACTORIES.get(script_type, _p2pkh)(pk)
                tx_outputs.append(TxOutput(amount=amount, script_pubkey=script))

        if not tx_inputs:
            return jsonify({"success": False, "error": "No inputs provided"})
        if not tx_outputs:
            return jsonify({"success": False, "error": "No outputs provided"})

        tx = Transaction(inputs=tx_inputs, outputs=tx_outputs)

        # ── Sign each input ───────────────────────────────────────────────
        for i, (inp, utxo) in enumerate(zip(tx.inputs, input_utxos)):
            sig_hash = tx.sighash(i, utxo.script_pubkey)
            stype    = _script_type(utxo.script_pubkey)

            if stype == "P2SH":
                # Collect M signatures from the registered co-signers
                sh       = utxo.script_pubkey.cmds[1].hex()
                rs_bytes = redeem_scripts.get(sh)
                info     = multisig_info.get(sh)
                if not rs_bytes or not info:
                    return jsonify({"success": False,
                                    "error": f"Input {i}: P2SH redeem script not registered"})
                sigs = []
                for signer in info["signers"][:info["m"]]:
                    sk_s = SigningKey.from_string(
                               ACCOUNTS[signer]["privkey_int"].to_bytes(32, "big"),
                               curve=SECP256k1)
                    sigs.append(sk_s.sign_digest(sig_hash) + b"\x01")
                inp.script_sig = [b""] + sigs + [rs_bytes]

            elif stype == "P2WSH":
                # P2WSH multisig: witness = [OP_0 dummy, sig1, …, witness_script]
                sh       = utxo.script_pubkey.cmds[1].hex()
                ws_bytes = witness_scripts.get(sh)
                info     = witness_script_info.get(sh)
                if not ws_bytes or not info:
                    return jsonify({"success": False,
                                    "error": f"Input {i}: P2WSH witness script not registered"})
                sigs = []
                for signer in info["signers"][:info["m"]]:
                    sk_s = SigningKey.from_string(
                               ACCOUNTS[signer]["privkey_int"].to_bytes(32, "big"),
                               curve=SECP256k1)
                    sigs.append(sk_s.sign_digest(sig_hash) + b"\x01")
                inp.witness = [b""] + sigs + [ws_bytes]

            elif stype == "P2WPKH":
                owner = _owner(utxo.script_pubkey)
                if owner not in ACCOUNTS:
                    return jsonify({"success": False,
                                    "error": f"Input {i}: cannot identify P2WPKH owner"})
                sk     = SigningKey.from_string(
                             ACCOUNTS[owner]["privkey_int"].to_bytes(32, "big"),
                             curve=SECP256k1)
                pubkey = sk.get_verifying_key().to_string()
                inp.witness = [sk.sign_digest(sig_hash) + b"\x01", pubkey]

            elif stype == "P2TR":
                owner = _owner(utxo.script_pubkey)
                if owner not in ACCOUNTS:
                    return jsonify({"success": False,
                                    "error": f"Input {i}: cannot identify P2TR owner"})
                sk = SigningKey.from_string(
                         ACCOUNTS[owner]["privkey_int"].to_bytes(32, "big"),
                         curve=SECP256k1)
                inp.witness = [sk.sign_digest(sig_hash) + b"\x01"]

            else:   # P2PKH / legacy
                owner = _owner(utxo.script_pubkey)
                if owner not in ACCOUNTS:
                    return jsonify({"success": False,
                                    "error": f"Input {i}: cannot identify owner"})
                sk      = SigningKey.from_string(
                              ACCOUNTS[owner]["privkey_int"].to_bytes(32, "big"),
                              curve=SECP256k1)
                pubkey  = sk.get_verifying_key().to_string()
                inp.script_sig = [sk.sign_digest(sig_hash) + b"\x01", pubkey]

        # ── Validate & apply ──────────────────────────────────────────────
        ok, msg = utxo_set.validate_and_apply(tx)

        total_in  = sum(u.amount for u in input_utxos)
        total_out = sum(o.amount for o in tx_outputs)

        def _inp_label(u):
            stype = _script_type(u.script_pubkey)
            if stype == "P2SH":
                c = u.script_pubkey.cmds
                sh = c[1].hex() if isinstance(c[1], bytes) else ""
                info = multisig_info.get(sh, {})
                return f"{info.get('m','?')}-of-{info.get('n','?')} P2SH ({', '.join(info.get('signers',[]))})"
            if stype == "P2WSH":
                c = u.script_pubkey.cmds
                sh = c[1].hex() if isinstance(c[1], bytes) else ""
                info = witness_script_info.get(sh, {})
                return f"{info.get('m','?')}-of-{info.get('n','?')} P2WSH ({', '.join(info.get('signers',[]))})"
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
            "outputs": [
                {"amount":      o.amount,
                 "recipient":   _owner(o.script_pubkey),
                 "script_type": _script_type(o.script_pubkey)}
                for o in tx_outputs
            ],
        }
        if ok:
            tx_history.append(record)
        return jsonify(record)

    except Exception as e:
        return jsonify({"success": False,
                        "error": str(e),
                        "traceback": traceback.format_exc()})


if __name__ == "__main__":
    print("\n  Bitcoin UTXO Visualizer")
    print("  ─────────────────────────────────────")
    print("  http://localhost:5000\n")
    app.run(debug=True, port=5000, use_reloader=False)
