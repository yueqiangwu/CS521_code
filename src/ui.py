import tkinter as tk

from common import opcode_2_op, VMError
from engine import BircoinScriptInterpreter
from script import Script


class InterpreterUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Bitcoin Script VM")

        tk.Label(root, text="Unlocking Script (ScriptSig)").pack()
        self.sig_input = tk.Entry(root, width=80)
        self.sig_input.pack()

        tk.Label(root, text="Locking Script (ScriptPubKey)").pack()
        self.pub_input = tk.Entry(root, width=80)
        self.pub_input.pack()

        frame = tk.Frame(root)
        frame.pack(pady=10)

        tk.Button(frame, text="Run All", command=self.run_all).pack(side=tk.LEFT)
        tk.Button(frame, text="Step", command=self.step).pack(side=tk.LEFT)
        tk.Button(frame, text="Reset", command=self.reset).pack(side=tk.LEFT)

        self.output = tk.Text(root, height=20, width=100)
        self.output.pack()

        self.vm = None

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def reset(self):
        self.vm = None
        self.output.delete(1.0, tk.END)

    def init_vm(self):
        try:
            sig = self.sig_input.get().strip()
            pub = self.pub_input.get().strip()

            full_script = f"{sig} {pub}"
            script = Script.parse(full_script)

            self.vm = BircoinScriptInterpreter(script)
            self.log("VM initialized.\n")
        except Exception as e:
            self.log(f"Initialzing error: {str(e)}")

    def step(self):
        if self.vm is None:
            self.init_vm()

        if self.vm.terminated:
            self.log("\nExecution finished.")
            return

        pc = self.vm.pc
        cmd = self.vm.script.cmds[pc]

        if isinstance(cmd, int):
            self.log(f"\nStep [{pc}] Executing: {opcode_2_op(cmd)}")
        else:
            self.log(f"\nStep [{pc}] Push Data: {cmd.hex()}")

        try:
            self.vm.step()
            self.show_stack()
        except VMError as e:
            self.log(f"Invalid transaction: {e.message}")
        except Exception as e:
            self.log(f"Executing error: {str(e)}")

    def run_all(self):
        if self.vm is None:
            self.init_vm()

        try:
            result = self.vm.execute()
            self.log("\nExecution finished.")
            self.show_stack()
            self.log(f"Result: {result}")
        except VMError as e:
            self.log(f"Invalid transaction: {e.message}")
        except Exception as e:
            self.log(f"Executing error: {str(e)}")

    def show_stack(self) -> str:
        self.log(f"Stack: [{", ".join(data.hex() for data in self.vm.stack)}]")
