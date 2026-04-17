import logging
import tkinter as tk

from ui import InterpreterUI
from transactions import *  #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s - %(message)s",
)


# <3045abcd> <02a1b2c3>
# OP_DUP OP_HASH160 <89abcdef> OP_EQUALVERIFY OP_CHECKSIG


if __name__ == "__main__":
    root = tk.Tk()
    app = InterpreterUI(root)
    root.mainloop()


