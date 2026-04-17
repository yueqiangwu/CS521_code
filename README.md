# CS521 Coding Project

### Topic 04A Bitcoin Script and Transaction Types

Group Members: Chenxin Yan & Yueqiang Wu

Presentation: Bitcoin's scripting language: design philosophy (intentionally not Turing complete), standard transaction types (P2PKH, P2SH, P2WPKH, P2WSH, multisig), Taproot/Schnorr upgrades, and security properties.

Coding project: Build a Bitcoin Script interpreter that parses and executes standard scripts on a stack machine. Demonstrate correct validation of multiple transaction types.

### Overview

A simple Bitcoin Script Interpreter based on Python

### Structure

```
bitcoin_script_interpreter/
├── src/
│   ├── __init__.py
│   ├── common.py          # Useful definitions
│   ├── engine.py          # Core Virtual Machine (VM) logic
│   ├── opcodes.py         # Definitions for all opcode functions
│   ├── crypto.py          # Cryptographic helper functions (Hash160, ECDSA verification)
│   ├── script.py          # Script parser: Converts ASM/HEX to a list of instructions
│   ├── main.py            # Project entry point: Demonstrates the execution process
│   └── ui.py              # Simple user interface
├── tests/
│   ├── __init__.py
│   ├── test_p2pkh.py      # P2PKH test cases
│   ├── test_p2sh.py       # P2SH test cases
│   ├── test_p2wpkh.py      # P2WPKH test cases
│   ├── test_p2wsh.py       # P2WSH test cases
│   └── test_multisig.py   # Multisig test cases
├── requirements.txt       # Dependencies (ecdsa, hashlib, etc.)
└── README.md
```

### Getting started

1. Clone repository `git clone https://github.com/yueqiangwu/CS521_code.git`

2. Install dependencies `pip install -r requirements.txt`

3. Run `python3 src/main.py` to show user interface

4. Run all tests `pytest -s tests/`
