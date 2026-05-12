# Bitcoin Script & Transaction Types — Interactive Visualizer

> **CS521 Coding Project · Topic 04A**
> Group Members: **Chenxin Yan** & **Yueqiang Wu**

🌐 **Live Demo:** https://cs-521-final-frontend.vercel.app/visualizer

---

## What is this project?

Bitcoin's scripting system is one of its most distinctive yet least understood components.
Rather than simple account-balance transfers, every Bitcoin coin is locked by a small
program (*scriptPubKey*) that a spending transaction must satisfy on a stack-based virtual
machine.

This project builds a **fully functional, interactive visualizer** for Bitcoin scripts and
transactions, covering every major standard from legacy P2PKH all the way through the 2021
Taproot upgrade (BIP340/341).

---

## Features

### 🔗 UTXO Pool & Transaction Builder
- Three pre-loaded accounts (Alice, Bob, Charlie) with genesis UTXOs
- Click any UTXO to select it as a transaction input
- Choose output recipient, amount, and script type from a dropdown
- Live fee calculation with automatic change-output suggestion
- Supports all five standard output types:
  `P2PKH` · `P2WPKH` · `P2TR` · `P2SH` · `P2WSH` · `P2TR MuSig`

### 🔐 Multisig UTXO Creation
- Create standalone M-of-N multisig UTXOs via a modal dialog
- P2SH (hash160, legacy) and P2WSH (sha256, native SegWit v0)
- **P2TR MuSig** (n-of-n): aggregates all signers' keys into a single Schnorr key via
  MuSig-style KeyAgg coefficients — indistinguishable from a single-key P2TR on-chain

### 🔬 Script Execution Replay
Every transaction input in the history carries a **🔬 replay button**.
- Color-coded instruction phases: `scriptSig` (amber) · `scriptPubKey` (blue) ·
  `witnessScript` (teal) · `redeemScript` (purple)
- Live stack visualization with type-annotated items (`sig`, `pubkey`, `hash160`, `TRUE`, …)
- Step navigation ⏮ ◀ ▶ ⏭
- **P2TR-specific view**: shows the BIP341 key tweak formula, Schnorr signature
  decomposition (R.x ‖ s), and the BIP341 taproot sighash structure with its
  unique `hashAmounts` and `hashScriptPubkeys` fields annotated

### 🔨 Transaction Malleability Demo
Every P2PKH and P2WPKH input carries a **🔨 malleation button** that:
1. Extracts the ECDSA signature (r, s) from the stored transaction
2. Computes the malleated signature (r, n − s) — both are valid under ECDSA
3. **P2PKH**: shows the TXID changes (signature is in scriptSig, which is hashed into the TXID)
4. **P2WPKH**: shows the TXID is unchanged (signature is in the witness, excluded from the TXID hash)

This concretely demonstrates why SegWit (BIP141) fixed the malleability vulnerability that
enabled attacks like the Mt. Gox exploit.

---

## Transaction Types Implemented

| Type | BIP | Signature | Malleability | Multisig |
|------|-----|-----------|--------------|----------|
| P2PKH | — | ECDSA in scriptSig | ⚠️ Vulnerable | — |
| P2SH | BIP16 | ECDSA in scriptSig | ⚠️ Vulnerable | M-of-N |
| P2WPKH | BIP141/143 | ECDSA in witness | ✅ Fixed | — |
| P2WSH | BIP141/143 | ECDSA in witness | ✅ Fixed | M-of-N |
| P2TR | BIP340/341 | Schnorr in witness | ✅ Fixed | N-of-N (MuSig) |

---

## Taproot / BIP341 Implementation

We implement the **complete BIP341 key-path P2TR** specification:

- **BIP340 Schnorr signatures** — deterministic 64-byte signatures, no DER encoding,
  no malleability
- **BIP341 key tweak** — `P_output = lift_x(P_internal) + H_TapTweak(P_internal.x) · G`,
  binding the output key to both the signing key and the (empty) script tree
- **BIP341 taproot sighash** — includes `hashAmounts` and `hashScriptPubkeys` over *all*
  inputs (not just the current one), preventing hardware-wallet amount-deception attacks
- **MuSig key aggregation** — `Q_agg = Σ aᵢ · lift_x(Pᵢ)` with KeyAgg coefficients,
  preventing rogue-key attacks, then taproot-tweaked before use in scriptPubKey

---

## Project Structure

```
CS521_code/
├── src/
│   ├── crypto.py          # SHA-256, HASH160, ECDSA, BIP340 Schnorr, BIP341 tweak, MuSig
│   ├── engine.py          # Stack-machine VM (used for validation)
│   ├── opcodes.py         # 80+ Bitcoin opcode implementations
│   ├── script.py          # ASM ↔ hex script parser / serializer
│   ├── transactions.py    # Per-type validation helpers (p2pkh, p2sh, p2wpkh, p2wsh, p2tr)
│   ├── utxo.py            # UTXO / Transaction model; legacy, BIP143, BIP341 sighash
│   ├── common.py          # Enums, error types, shared constants
│   └── app.py             # Flask API for the script interpreter (step-through sessions)
├── templates/
│   └── index.html         # Single-page interactive UTXO visualizer frontend
├── tests/
│   ├── test_p2pkh.py      # 7 tests
│   ├── test_p2sh.py       # 8 tests
│   ├── test_p2wpkh.py     # 7 tests
│   ├── test_p2wsh.py      # 8 tests
│   ├── test_p2tr.py       # 36 tests (BIP340/341, key tweak, MuSig, UTXOSet end-to-end)
│   └── test_utxo.py       # 14 tests
├── web_app.py             # Main Flask server (UTXO visualizer + script interpreter APIs)
├── requirements.txt       # Python dependencies
└──Procfile               # Deployment (gunicorn web_app:app)
```

---

## Getting Started

### Prerequisites

```bash
pip install -r requirements.txt
```

### Run locally

```bash
python web_app.py
# Open http://localhost:5000
```

### Run tests

```bash
pytest tests/ --ignore=tests/test_interpreter.py -v
# 80 tests should pass
```

---

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/state` | GET | Current UTXO pool |
| `/api/history` | GET | Last 30 transactions |
| `/api/transact` | POST | Build, sign, validate and apply a transaction |
| `/api/create_multisig` | POST | Create a standalone multisig UTXO |
| `/api/replay` | POST | Step-through script execution replay |
| `/api/malleate` | POST | ECDSA malleability demonstration |
| `/api/reset` | POST | Restore genesis state |
| `/api/step` | POST | Script interpreter step (session-based) |

---

## Tech Stack

- **Backend:** Python 3.11, Flask, ecdsa library (secp256k1)
- **Frontend:** Vanilla JS, Bootstrap 5.3
- **Crypto:** Pure-Python BIP340/341 implementation (no external Taproot library)
- **Deploy:** Gunicorn on Render.com
