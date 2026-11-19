"""Hash-chained, tamper-evident event log with optional JSON persistence.

This is a single-node integrity log, not a distributed blockchain: there is no
consensus or replication. Anyone who can rewrite the whole file can also
recompute every hash, so keep chain.json somewhere only the service can write.
"""

import hashlib
import json
import os
import tempfile
import threading
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

GENESIS_EVENT = "Genesis Block"
REQUIRED_KEYS = {"index", "timestamp", "event", "previous_hash", "hash"}


def _normalize(value):
    # Whole-number floats are written as integers (100.0 -> 100) so the hash
    # input is identical to the web app's JavaScript serializer.
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


def canonical_json(value):
    """The one hash format used everywhere: sorted keys, compact separators, UTF-8."""
    return json.dumps(_normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class ChainIntegrityError(ValueError):
    """Raised when a loaded chain fails verification."""

    def __init__(self, bad_index, reason):
        super().__init__(f"Chain integrity check failed at block {bad_index}: {reason}")
        self.bad_index = bad_index
        self.reason = reason


class Blockchain:
    def __init__(self, path=None, autosave=True, strict=True):
        """Create a chain. With ``path`` set, load it from disk when the file exists
        (verifying it) and save after every append when ``autosave`` is true.

        ``strict=True`` raises ChainIntegrityError for a tampered file; with
        ``strict=False`` the chain is loaded anyway so callers can report the
        first bad block (see ``integrity``)."""
        self._lock = threading.RLock()
        self.path = Path(path) if path else None
        self.autosave = autosave
        self.chain = []
        self.integrity = (True, None, None)
        if self.path and self.path.is_file():
            self.load(self.path, strict=strict)
        else:
            self.create_block(GENESIS_EVENT, "0")

    def calculate_hash(self, block):
        return hashlib.sha256(canonical_json(block).encode("utf-8")).hexdigest()

    def create_block(self, event, previous_hash):
        with self._lock:
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
            if self.path and self.autosave:
                self.save()
            return block

    def add_block(self, event):
        # The lock covers reading the tip and appending, so concurrent callers
        # can never link two blocks to the same previous hash.
        with self._lock:
            previous_hash = self.chain[-1]["hash"]
            return self.create_block(event, previous_hash)

    def verify_chain_detailed(self):
        """Return (ok, bad_index, reason). ``bad_index`` is the 1-based block
        index of the first invalid block, or None when the chain is valid."""
        with self._lock:
            blocks = list(self.chain)
        if not blocks:
            return False, None, "Chain is empty."
        previous_hash = "0"
        for i, block in enumerate(blocks):
            position = i + 1
            if not isinstance(block, dict) or set(block) != REQUIRED_KEYS:
                return False, position, "Block fields are missing or unexpected."
            if block["index"] != position:
                return False, position, "Block index is out of sequence."
            if block["previous_hash"] != previous_hash:
                return False, position, "Previous hash does not match the prior block."
            if i == 0 and block["event"] != GENESIS_EVENT:
                return False, position, "Genesis block was modified."
            try:
                expected_hash = self.calculate_hash(
                    {k: v for k, v in block.items() if k != "hash"}
                )
            except (TypeError, ValueError):
                return False, position, "Block content cannot be hashed."
            if block["hash"] != expected_hash:
                return False, position, "Block content does not match its hash."
            previous_hash = block["hash"]
        return True, None, None

    def verify_chain(self):
        return self.verify_chain_detailed()[0]

    def save(self, path=None):
        """Write the chain atomically: temp file in the same folder, then rename."""
        target = Path(path) if path else self.path
        if target is None:
            raise ValueError("No path given for saving the chain.")
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            payload = json.dumps(self.chain, indent=2)
            fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_name, target)
            except BaseException:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
                raise
        return target

    def load(self, path=None, strict=True):
        source = Path(path) if path else self.path
        if source is None:
            raise ValueError("No path given for loading the chain.")
        with open(source, encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, list):
            raise ChainIntegrityError(None, "Chain file must contain a list of blocks.")
        with self._lock:
            self.chain = data
            self.integrity = self.verify_chain_detailed()
        ok, bad_index, reason = self.integrity
        if not ok and strict:
            raise ChainIntegrityError(bad_index, reason)
        return self.integrity


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
