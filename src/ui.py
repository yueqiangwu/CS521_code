import customtkinter as ctk
import json
import logging
import os

from common import TX_HASH_SIZE, generate_asm_script
from crypto import hash160, sha256, generate_sig_pair
from engine import BitcoinScriptInterpreter
from script import Script
from opcodes import opcode_2_op
from tkinter import messagebox, filedialog


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class BitcoinIDE(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Bitcoin Script Visual Interpreter")
        self.geometry("1920x1080")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.vm = None
        self.instructions = []
        self.current_tx_hash = os.urandom(TX_HASH_SIZE)

        self._setup_sidebar()
        self._setup_editor_area()
        self._setup_runtime_view()

    # ========== Draw functions ==========

    def _setup_sidebar(self):
        """
        Sidebar: script templates & document manipulations
        """
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        ctk.CTkLabel(self.sidebar, text="Presets", font=("Roboto", 20, "bold")).pack(
            pady=10
        )

        presets = {
            "P2PK": self._load_p2pk_template,
            "P2PKH": self._load_p2pkh_template,
            "P2SH": self._load_p2sh_template,
            "P2WPKH": self._load_p2wpkh_template,
            "P2WSH": self._load_p2wsh_template,
        }

        for name, func in presets.items():
            ctk.CTkButton(
                self.sidebar,
                text=name,
                command=func,
                fg_color="transparent",
                border_width=1,
            ).pack(pady=5, padx=10, fill="x")

        ctk.CTkLabel(self.sidebar, text="File Ops", font=("Roboto", 16)).pack(
            pady=(20, 10)
        )
        ctk.CTkButton(self.sidebar, text="Save Script", command=self.save_to_file).pack(
            pady=5, padx=10, fill="x"
        )
        ctk.CTkButton(
            self.sidebar, text="Load Script", command=self.load_from_file
        ).pack(pady=5, padx=10, fill="x")

    def _setup_editor_area(self):
        """
        Editor area: ScriptSig, ScriptPubKey, Witness
        """
        self.editor_frame = ctk.CTkFrame(self)
        self.editor_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        # TX Hash
        ctk.CTkLabel(self.editor_frame, text="TX Hash (random)").pack(
            anchor="w", padx=10
        )
        self.tx_hash_input = ctk.CTkTextbox(self.editor_frame, height=20)
        self.tx_hash_input.pack(fill="x", padx=10, pady=5)
        self.tx_hash_input.insert("1.0", self.current_tx_hash.hex())

        # ScriptSig
        ctk.CTkLabel(self.editor_frame, text="ScriptSig (Unlocking Script)").pack(
            anchor="w", padx=10
        )
        self.sig_input = ctk.CTkTextbox(self.editor_frame, height=80)
        self.sig_input.pack(fill="x", padx=10, pady=5)

        # ScriptPubKey
        ctk.CTkLabel(self.editor_frame, text="ScriptPubKey (Locking Script)").pack(
            anchor="w", padx=10
        )
        self.pub_input = ctk.CTkTextbox(self.editor_frame, height=80)
        self.pub_input.pack(fill="x", padx=10, pady=5)

        # Witness
        ctk.CTkLabel(self.editor_frame, text="Witness Data (for SegWit)").pack(
            anchor="w", padx=10
        )
        self.witness_input = ctk.CTkTextbox(self.editor_frame, height=100)
        self.witness_input.pack(fill="x", padx=10, pady=5)

        # control buttons
        self.ctrl_frame = ctk.CTkFrame(self.editor_frame, fg_color="transparent")
        self.ctrl_frame.pack(fill="x", pady=10)

        self.btn_step = ctk.CTkButton(
            self.ctrl_frame, text="Step Over", command=self.step, width=100
        )
        self.btn_step.pack(side="left", padx=10)

        self.btn_run = ctk.CTkButton(
            self.ctrl_frame,
            text="Run All",
            command=self.run_all,
            width=100,
            fg_color="green",
        )
        self.btn_run.pack(side="left", padx=10)

        self.btn_reset = ctk.CTkButton(
            self.ctrl_frame,
            text="Reset",
            command=self.reset,
            width=100,
            fg_color="gray",
        )
        self.btn_reset.pack(side="left", padx=10)

        self.btn_clear_all = ctk.CTkButton(
            self.ctrl_frame,
            text="Clear All",
            command=self.clear_all,
            width=100,
            fg_color="orange",
        )
        self.btn_clear_all.pack(side="left", padx=10)

    def _setup_runtime_view(self):
        """
        View area: instruction lists & stack
        """
        self.runtime_frame = ctk.CTkFrame(self.editor_frame)
        self.runtime_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # instruction list
        self.ins_container = ctk.CTkScrollableFrame(
            self.runtime_frame, label_text="Instruction Pipeline"
        )
        self.ins_container.pack(side="left", fill="both", expand=True, padx=5)

        # stack
        self.stack_container = ctk.CTkScrollableFrame(
            self.runtime_frame, label_text="Data Stack (Bottom is Top)"
        )
        self.stack_container.pack(side="right", fill="both", expand=True, padx=5)

    # ========== Load templates ==========

    def _load_p2pk_template(self):
        logging.info("Loading P2PK template...")

        self.clear_all()
        self.current_tx_hash = os.urandom(TX_HASH_SIZE)

        pk, sig = generate_sig_pair(self.current_tx_hash)
        scriptSig = generate_asm_script("<{}> # sig", sig)
        scriptPubkey = generate_asm_script("<{}> # pubkey\nOP_CHECKSIG", pk)

        self.tx_hash_input.insert("1.0", self.current_tx_hash.hex())
        self.sig_input.insert("1.0", scriptSig)
        self.pub_input.insert("1.0", scriptPubkey)

        self.init_vm()

    def _load_p2pkh_template(self):
        logging.info("Loading P2PKH template...")

        self.clear_all()
        self.current_tx_hash = os.urandom(TX_HASH_SIZE)

        pk, sig = generate_sig_pair(self.current_tx_hash)
        pkh = hash160(pk)
        scriptSig = generate_asm_script("<{}> # sig\n<{}> # pubkey", sig, pk)
        scriptPubkey = generate_asm_script(
            "OP_DUP\nOP_HASH160\n<{}> # pubkey hash\nOP_EQUALVERIFY\nOP_CHECKSIG", pkh
        )

        self.tx_hash_input.insert("1.0", self.current_tx_hash.hex())
        self.sig_input.insert("1.0", scriptSig)
        self.pub_input.insert("1.0", scriptPubkey)

        self.init_vm()

    def _load_p2sh_template(self):
        logging.info("Loading P2SH template...")

        self.clear_all()
        self.current_tx_hash = os.urandom(TX_HASH_SIZE)

        pk1, sig1 = generate_sig_pair(self.current_tx_hash)
        pk2, sig2 = generate_sig_pair(self.current_tx_hash)
        redeem_script_asm = generate_asm_script(
            "OP_2 <{}> <{}> OP_2 OP_CHECKMULTISIG", pk1, pk2
        )
        redeem_script_bytes = Script.parse(redeem_script_asm).serialize()
        redeem_script_hash = hash160(redeem_script_bytes)
        scriptSig = generate_asm_script(
            "OP_0\n<{}>\n<{}> # sig1 sig2 ...\n{{{}}} # redeem script (pubkey1 pubkey2 ...)",
            sig1,
            sig2,
            redeem_script_asm,
        )
        scriptPubkey = generate_asm_script(
            "OP_HASH160\n<{}> # redeem script hash\nOP_EQUAL", redeem_script_hash
        )

        self.tx_hash_input.insert("1.0", self.current_tx_hash.hex())
        self.sig_input.insert("1.0", scriptSig)
        self.pub_input.insert("1.0", scriptPubkey)

        self.init_vm()

    def _load_p2wpkh_template(self):
        logging.info("Loading P2WPKH template...")

        self.clear_all()
        self.current_tx_hash = os.urandom(TX_HASH_SIZE)

        pk, sig = generate_sig_pair(self.current_tx_hash)
        pkh = hash160(pk)

        scriptSig = ""
        scriptPubkey = generate_asm_script("OP_0\n<{}> # pubkey hash", pkh)
        witness = generate_asm_script("<{}> # sig\n<{}> # pubkey", sig, pk)

        self.tx_hash_input.insert("1.0", self.current_tx_hash.hex())
        self.sig_input.insert("1.0", scriptSig)
        self.pub_input.insert("1.0", scriptPubkey)
        self.witness_input.insert("1.0", witness)

        self.init_vm()

    def _load_p2wsh_template(self):
        logging.info("Loading P2WSH template...")

        self.reset()
        self.current_tx_hash = os.urandom(TX_HASH_SIZE)

        pk, sig = generate_sig_pair(self.current_tx_hash)
        witness_script_asm = generate_asm_script("<{}> # pubkey\nOP_CHECKSIG", pk)
        witness_script_bytes = Script.parse(witness_script_asm).serialize()
        witness_script_hash = sha256(witness_script_bytes)

        scriptSig = ""
        scriptPubkey = generate_asm_script(
            "OP_0\n<{}> # witness script hash", witness_script_hash
        )
        witness = generate_asm_script(
            "<{}> # sig\n{{{}}} # witness script", sig, witness_script_asm
        )

        self.tx_hash_input.insert("1.0", self.current_tx_hash.hex())
        self.sig_input.insert("1.0", scriptSig)
        self.pub_input.insert("1.0", scriptPubkey)
        self.witness_input.insert("1.0", witness)

        self.init_vm()

    # ========== VM operating functions ==========

    def init_vm(self) -> bool:
        if self.vm is not None:
            return True

        try:
            sig_text = self.sig_input.get("1.0", "end").strip()
            pub_text = self.pub_input.get("1.0", "end").strip()
            witness_text = self.witness_input.get("1.0", "end").strip()

            full_script_hex = f"{sig_text}\n{pub_text}"
            script = Script.parse(full_script_hex)
            witness_script = Script.parse(witness_text)
            witness = witness_script.cmds

            self.vm = BitcoinScriptInterpreter(
                script, witness=witness, tx_sig_hash=self.current_tx_hash
            )
            self.instructions = []
            for cmd in script.cmds:
                self.instructions.append(
                    opcode_2_op(cmd) if isinstance(cmd, int) else f"PUSH({cmd.hex()})"
                )

            self._update_ins_list()
            self._lock_inputs(True)
            return True
        except Exception as e:
            logging.exception(e)
            messagebox.showerror("Error", f"Failed to initialize: {e}")
            return False

    def step(self):
        if not self.init_vm():
            return

        if self.vm.terminated:
            logging.info("Execution already finished")

            self._show_result()
            return

        try:
            self.vm.step()
            self._update_ui_state()

            if self.vm.terminated:
                logging.info("Execution finished")

                self._show_result()
        except Exception as e:
            logging.exception(e)
            messagebox.showerror("VM Error", str(e))

    def run_all(self):
        if not self.init_vm():
            return

        if self.vm.terminated:
            logging.info("Execution already finished")

            self._show_result()
            return

        try:
            while not self.vm.terminated:
                self.vm.step()
        except Exception as e:
            logging.exception(e)
            messagebox.showerror("VM Error", str(e))
            return

        self._update_ui_state()
        self._show_result()

    def reset(self):
        self.vm = None
        self.instructions.clear()

        self._lock_inputs(False)
        self._update_ui_state(clear=True)

    def clear_all(self):
        self.reset()

        self.tx_hash_input.delete("1.0", "end")
        self.sig_input.delete("1.0", "end")
        self.pub_input.delete("1.0", "end")
        self.witness_input.delete("1.0", "end")

    # ========== UI updates ==========

    def _lock_inputs(self, lock: bool):
        state = "disabled" if lock else "normal"
        self.tx_hash_input.configure(state=state)
        self.sig_input.configure(state=state)
        self.pub_input.configure(state=state)
        self.witness_input.configure(state=state)

    def _update_ui_state(self, clear: bool = False):
        self._update_ins_list(clear)
        self._update_stack_view(clear)

    def _update_ins_list(self, clear: bool = False):
        """
        Clear and redraw the command list
        """
        for widget in self.ins_container.winfo_children():
            widget.destroy()

        if clear:
            return

        # Retrieve the currently truly active virtual machines
        current_vm = self.vm
        prefix_title = "Main"
        while current_vm.active_inner_vm:
            current_vm = current_vm.active_inner_vm
            prefix_title = "Inner"

        for i, cmd in enumerate(current_vm.script.cmds):
            text = opcode_2_op(cmd) if isinstance(cmd, int) else f"PUSH({cmd.hex()})"
            is_previous = i < current_vm.pc
            is_current = i == current_vm.pc

            if is_previous:
                text_color = "#76CA84"
            elif is_current:
                text_color = "#FFCC00"
            else:
                text_color = "white"

            lbl = ctk.CTkLabel(
                self.ins_container,
                text=f"{prefix_title} [{i:02d}] {text}",
                fg_color="#3B3B3B" if is_current else "transparent",
                text_color=text_color,
                anchor="w",
            )
            lbl.pack(fill="x", padx=5, pady=2)

    def _update_stack_view(self, clear: bool = False):
        """
        Redraw stack contents
        """
        for widget in self.stack_container.winfo_children():
            widget.destroy()

        if clear:
            return

        current_vm = self.vm
        while current_vm.active_inner_vm:
            current_vm = current_vm.active_inner_vm

        for i, item in enumerate(current_vm.stack):
            val = item.hex() if isinstance(item, bytes) else str(item)
            frame = ctk.CTkFrame(self.stack_container, height=30)
            frame.pack(fill="x", padx=5, pady=2)
            ctk.CTkLabel(
                frame, text=f"Index {i}", text_color="gray", font=("", 10)
            ).pack(side="left", padx=5)
            ctk.CTkLabel(frame, text=val).pack(side="right", padx=5)

    def _show_result(self):
        valid = self.vm._is_valid()
        message = "Transaction Success!" if valid else "Transaction Failed."
        messagebox.showinfo("Result", message)

    # ========== File operating functions ==========

    def save_to_file(self):
        data = {
            "ScriptSig": self.sig_input.get("1.0", "end").strip(),
            "ScriptPubKey": self.pub_input.get("1.0", "end").strip(),
            "Witness": self.witness_input.get("1.0", "end").strip().split("\n"),
        }

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text files", "*.txt")]
        )

        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

            messagebox.showinfo("Success", "Script saved successfully!")

    def load_from_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])

        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                self.reset()
                self.sig_input.insert("1.0", data.get("ScriptSig", ""))
                self.pub_input.insert("1.0", data.get("ScriptPubKey", ""))
                witness_list = data.get("Witness", [])
                self.witness_input.insert("1.0", "\n".join(witness_list))
            except Exception as e:
                logging.exception(e)
                messagebox.showerror("Error", f"Invalid file format: {e}")
