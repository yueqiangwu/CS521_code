# CS521 Coding Project

### Topic 04A Bitcoin Script and Transaction Types

Group Members: Chenxin Yan & Yueqiang Wu

Presentation: Bitcoin's scripting language: design philosophy (intentionally not Turing complete), standard transaction types (P2PKH, P2SH, P2WPKH, P2WSH, multisig), Taproot/Schnorr upgrades, and security properties.

Coding project: Build a Bitcoin Script interpreter that parses and executes standard scripts on a stack machine. Demonstrate correct validation of multiple transaction types.

### Overview

A simple Bitcoin Script Interpreter based on Python flask backend & React frontend

### Structure

```
bitcoin_script_interpreter/
├── src/
│   ├── frontend/          # Frontend related files
│   ├── app.py             # Backend flask server
│   ├── common.py          # Useful definitions
│   ├── crypto.py          # Cryptographic helper functions
│   ├── engine.py          # Core Virtual Machine (VM) logic
│   ├── main.py            # Tkinter UI entry point
│   ├── opcodes.py         # Definitions for all opcode functions
│   ├── script.py          # Script parser
│   ├── templates.py       # Store transaction templates
│   ├── transactions.py    # Dealing with different transactions
│   └── ui.py              # Simple user interface
├── tests/                 # PyTest related files
├── requirements.txt       # Dependencies (ecdsa, hashlib, etc.)
└── README.md
```

### Getting started

1. Clone repository `git clone https://github.com/yueqiangwu/CS521_code.git`

2. Install backend dependencies `pip install -r requirements.txt`

3. For Tkinter UI, run `python3 src/main.py`

4. For web UI, run `python3 src/app.py` to launch flask server

5. Install frontend dependencies `cd src/frontend` `npm install`

6. Then run `npm run start` to launch frontend

7. For PyTest, use `pytest -s tests/` to run all tests
