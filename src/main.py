import logging

from ui import BitcoinIDE

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(filename)s - %(message)s",
)

if __name__ == "__main__":
    app = BitcoinIDE()
    app.mainloop()
