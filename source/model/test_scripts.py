import contextlib
import io
from pathlib import Path
import tempfile
import unittest

import joblib
import pandas as pd

from blockchain import Blockchain
from train_model import prepare_features, train


class BlockchainTests(unittest.TestCase):
    def test_valid_chain_and_event_snapshot(self):
        chain = Blockchain()
        event = {"details": {"attempts": 3}}
        chain.add_block(event)
        event["details"]["attempts"] = 9
        self.assertEqual(chain.chain[1]["event"]["details"]["attempts"], 3)
        self.assertTrue(chain.verify_chain())

    def test_tampering(self):
        for field, value in [("event", "changed"), ("previous_hash", "bad"), ("index", 99)]:
            with self.subTest(field=field):
                chain = Blockchain()
                chain.add_block({"attempts": 3})
                chain.chain[1][field] = value
                self.assertFalse(chain.verify_chain())

    def test_genesis_and_empty_chain(self):
        chain = Blockchain()
        chain.chain[0]["previous_hash"] = "bad"
        chain.chain[0]["hash"] = chain.calculate_hash(
            {k: v for k, v in chain.chain[0].items() if k != "hash"}
        )
        self.assertFalse(chain.verify_chain())
        chain.chain.clear()
        self.assertFalse(chain.verify_chain())

    def test_missing_hash(self):
        chain = Blockchain()
        del chain.chain[0]["hash"]
        self.assertFalse(chain.verify_chain())

    def test_invalid_link_rejected(self):
        chain = Blockchain()
        with self.assertRaises(ValueError):
            chain.create_block("event", "invalid")
        self.assertEqual(len(chain.chain), 1)


class TrainingTests(unittest.TestCase):
    def test_target_leakage_excluded(self):
        df = pd.DataFrame({"id": range(4), "attack_cat": ["Normal", "Attack"] * 2,
                           "label": [0, 1] * 2, "bytes": [2, 8, 4, 9]})
        features, target = prepare_features(df)
        self.assertEqual(list(features.columns), ["bytes"])
        self.assertEqual(target.tolist(), [0, 1, 0, 1])

    def test_invalid_labels(self):
        for labels in [[0, 0, 0, 0], [0, 1, None, 1], [0, 1, 2, 1]]:
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                prepare_features(pd.DataFrame({"label": labels, "bytes": [1, 2, 3, 4]}))

    def test_training_and_saved_pipeline(self):
        # Synthetic fixtures validate execution, not real-world detection accuracy.
        df = pd.DataFrame({
            "id": range(40), "label": [0, 1] * 20,
            "attack_cat": ["Normal", "Attack"] * 20,
            "proto": ["tcp", "udp"] * 20,
            "bytes": [None if i % 7 == 0 else i + 1 for i in range(40)],
        })
        with tempfile.TemporaryDirectory() as directory:
            csv = Path(directory) / "fixture.csv"
            output = Path(directory) / "model.pkl"
            df.to_csv(csv, index=False)
            with contextlib.redirect_stdout(io.StringIO()):
                trained = train(csv, output)
            restored = joblib.load(output)
            sample = pd.DataFrame({"proto": ["unseen-protocol"], "bytes": [None]})
            self.assertEqual(restored.predict(sample).tolist(), trained.predict(sample).tolist())
            self.assertEqual(restored.feature_names_in_.tolist(), ["proto", "bytes"])


if __name__ == "__main__":
    unittest.main()
