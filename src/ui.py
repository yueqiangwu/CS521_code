import customtkinter as ctk
import json

from tkinter import messagebox, filedialog
from common import VMError
from engine import BitcoinScriptInterpreter
from script import Script
from opcodes import opcode_2_op


ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class BitcoinIDE(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Bitcoin Script Visual Debugger")
        self.geometry("1100x800")

        self.vm = None
        self.instructions = []

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._setup_sidebar()
        self._setup_editor_area()
        self._setup_runtime_view()

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
            "P2PKH": self.load_p2pkh_template,
            "P2SH": self.load_p2sh_template,
            "P2WPKH": self.load_p2wpkh_template,
            "P2WSH": self.load_p2wsh_template,
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
        ctk.CTkLabel(
            self.editor_frame, text="Witness Data (for SegWit, one per line)"
        ).pack(anchor="w", padx=10)
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

    def init_vm(self) -> bool:
        if self.vm:
            return True

        try:
            sig_text = self.sig_input.get("1.0", "end").strip()
            pub_text = self.pub_input.get("1.0", "end").strip()
            witness_text = self.witness_input.get("1.0", "end").strip()

            witness = [bytes.fromhex(x) for x in witness_text.split() if x]

            full_script_hex = f"{sig_text} {pub_text}"
            script = Script.parse(full_script_hex)

            self.vm = BitcoinScriptInterpreter(script, witness=witness)
            self.instructions = []
            for cmd in script.cmds:
                self.instructions.append(
                    opcode_2_op(cmd) if isinstance(cmd, int) else f"PUSH({cmd.hex()})"
                )

            self._update_ins_list()
            self._lock_inputs(True)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize: {e}")
            return False

    def step(self):
        if not self.init_vm():
            return

        if self.vm.terminated:
            self._show_result()
            return

        try:
            self.vm.step()
            self._update_ui_state()
        except Exception as e:
            messagebox.showerror("VM Error", str(e))

    def run_all(self):
        if not self.init_vm():
            return

        try:
            while not self.vm.terminated:
                self.vm.step()
        except Exception as e:
            messagebox.showerror("VM Error", str(e))
            return

        self._update_ui_state()
        self._show_result()

    def reset(self):
        self.vm = None
        self._lock_inputs(False)
        self._update_ins_list(clear=True)
        self._update_stack_view(clear=True)

    def _update_ui_state(self):
        self._update_ins_list()
        self._update_stack_view()

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

    def _lock_inputs(self, lock: bool):
        state = "disabled" if lock else "normal"
        self.sig_input.configure(state=state)
        self.pub_input.configure(state=state)
        self.witness_input.configure(state=state)

    def _show_result(self):
        valid = self.vm.is_valid()
        color = "green" if valid else "red"
        messagebox.showinfo("Result", f"Transaction Valid: {valid}")

    def load_p2pkh_template(self):
        self.reset()
        self.sig_input.insert("1.0", "<your sig> <your pubkey>")
        self.pub_input.insert(
            "1.0", "OP_DUP OP_HASH160 <your pubkey hash> OP_EQUALVERIFY OP_CHECKSIG"
        )

    def load_p2sh_template(self):
        # TODO
        pass

    def load_p2wpkh_template(self):
        # TODO
        pass

    def load_p2wsh_template(self):
        # TODO
        pass

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
                messagebox.showerror("Error", f"Invalid file format: {e}")
