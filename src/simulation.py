import hashlib
import uuid

from common import VMError
from engine_v2 import BitcoinScriptInterpreterV2
from script import Script


def generate_hash():
    return hashlib.sha256(str(uuid.uuid4()).encode())


class UTXO:
    """
    Unspent outputs stored in the global database
    """

    def __init__(self, tx_hash: bytes, vout: int, amount: int, script_pubkey: Script):
        self.tx_hash = tx_hash
        self.vout = vout
        self.amount = amount
        self.script_pubkey = script_pubkey


class TransactionInput:
    """
    Points to an old UTXO and provides the unlocking credentials
    """

    def __init__(self, prev_tx_hash: bytes, prev_vout: int):
        self.prev_tx_hash = prev_tx_hash
        self.prev_vout = prev_vout
        self.script_sig = Script()
        self.witness = Script()


class TransactionOutput:
    """
    Create New Payment Destination
    """

    def __init__(self, amount: int, script_pubkey: Script):
        self.amount = amount
        self.script_pubkey = script_pubkey


class Transaction:
    """
    Transaction body
    """

    def __init__(
        self, inputs: list[TransactionInput], outputs: list[TransactionOutput]
    ):
        self.tx_hash = (
            generate_hash()
        )  # Simplification: Directly generate a random hash to simulate a TXID
        self.inputs = inputs
        self.outputs = outputs


class BlockchainNode:
    def __init__(self):
        # Simulated Global UTXO Database: (tx_hash, vout) -> UTXO_Object
        self.utxo_set: dict[tuple[bytes, int], UTXO] = {}

    def add_to_utxo_set(self, utxo):
        self.utxo_set[(utxo.tx_hash, utxo.vout)] = utxo

    def verify_transaction(self, tx: Transaction) -> bool:
        print(f"Start Verifying Transaction: {tx.tx_hash}...")

        total_input_value = 0

        # Core Logic: Validate each input individually
        for i, tx_in in enumerate(tx.inputs):
            # 1. Check if the referenced UTXO exists
            utxo_key = (tx_in.prev_tx_hash, tx_in.prev_vout)
            referenced_utxo = self.utxo_set.get(utxo_key)

            if referenced_utxo is None:
                print(
                    f"Verification failed: The UTXO referenced by input {i} does not exist or has already been spent."
                )
                return False

            total_input_value += referenced_utxo.amount

            # 2. Invoke the virtual machine to perform script validation
            vm = BitcoinScriptInterpreterV2(
                tx.tx_hash,
                tx_in.script_sig,
                referenced_utxo.script_pubkey,
                tx_in.witness,
            )
            while not vm.is_terminated:
                vm.step()

            if not vm.is_valid():
                print(f"Verification Failed: Script validation for input {i} failed.")
                return False

        # 3. Check Amount (Input must be sufficient to cover the output)
        total_output_value = sum(out.amount for out in tx.outputs)
        if total_input_value < total_output_value:
            print("Verification Failed: Insufficient Amount")
            return False

        print("Transaction verified! Ready to be written to the block.")
        return True


# --- Simulation ---

# 1. Initialize the node and mint some initial funds (UTXO)
node = BlockchainNode()
fake_utxo_1 = UTXO(
    generate_hash(), 0, 0.5, "OP_DUP OP_HASH160 <Hash1> OP_EQUALVERIFY OP_CHECKSIG"
)
fake_utxo_2 = UTXO(
    generate_hash(), 1, 0.8, "OP_DUP OP_HASH160 <Hash2> OP_EQUALVERIFY OP_CHECKSIG"
)
node.add_to_utxo_set(fake_utxo_1)
node.add_to_utxo_set(fake_utxo_2)

# 2. Constructing a new transaction and attempting to spend these two. UTXO
in1 = TransactionInput(fake_utxo_1.tx_hash, 0)
in1.script_sig = "<Sig1> <PubKey1>"

in2 = TransactionInput(fake_utxo_2.tx_hash, 1)
in2.script_sig = "<Sig2> <PubKey2>"

out1 = TransactionOutput(
    1.2, "OP_DUP OP_HASH160 <ReceiverHash> OP_EQUALVERIFY OP_CHECKSIG"
)
out2 = TransactionOutput(
    0.09, "OP_DUP OP_HASH160 <SenderHash> OP_EQUALVERIFY OP_CHECKSIG"
)

my_tx = Transaction([in1, in2], [out1, out2])

# 3. Node Verification
node.verify_transaction(my_tx)
