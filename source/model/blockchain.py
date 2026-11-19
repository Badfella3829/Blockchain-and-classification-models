import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_block("Genesis Block", "0")

    def calculate_hash(self, block):
        block_data = json.dumps(
            block, sort_keys=True
        ).encode()

        return hashlib.sha256(block_data).hexdigest()

    def create_block(self, event, previous_hash):
        expected_hash = self.chain[-1]["hash"] if self.chain else "0"
        if previous_hash != expected_hash:
            raise ValueError("Previous hash must match the current chain tip.")
        block = {
            "index": len(self.chain) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": deepcopy(event),
            "previous_hash": previous_hash
        }

        block["hash"] = self.calculate_hash(block)
        self.chain.append(block)
        return block

    def add_block(self, event):
        previous_hash = self.chain[-1]["hash"]
        return self.create_block(event, previous_hash)

    def verify_chain(self):
        if not self.chain:
            return False
        previous_hash = "0"
        required_keys = {"index", "timestamp", "event", "previous_hash", "hash"}
        for i, block in enumerate(self.chain):
            if not isinstance(block, dict) or set(block) != required_keys:
                return False
            if block["index"] != i + 1 or block["previous_hash"] != previous_hash:
                return False
            if i == 0 and block["event"] != "Genesis Block":
                return False
            try:
                expected_hash = self.calculate_hash(
                    {k: v for k, v in block.items() if k != "hash"}
                )
            except (TypeError, ValueError):
                return False
            if block["hash"] != expected_hash:
                return False
            previous_hash = block["hash"]
        return True


# Testing the blockchain
if __name__ == "__main__":
    bc = Blockchain()
    bc.add_block({
        "event_id": "E101",
        "username": "Rahul",
        "failed_attempts": 15,
        "severity": "High"
    })
    bc.add_block({
        "event_id": "E102",
        "username": "Aman",
        "failed_attempts": 8,
        "severity": "Medium"
    })
    for block in bc.chain:
        print(block)
    print("Blockchain valid:", bc.verify_chain())
