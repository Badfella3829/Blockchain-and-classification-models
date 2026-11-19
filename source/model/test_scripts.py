import contextlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest

import joblib
import pandas as pd

from blockchain import Blockchain, ChainIntegrityError, canonical_json
from train_model import generate_synthetic_dataset, prepare_features, train
from web_model import WebModel


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

    def test_detailed_verify_reports_first_bad_block(self):
        chain = Blockchain()
        for i in range(4):
            chain.add_block({"n": i})
        self.assertEqual(chain.verify_chain_detailed(), (True, None, None))
        chain.chain[2]["event"] = {"n": 999}
        ok, bad_index, reason = chain.verify_chain_detailed()
        self.assertFalse(ok)
        self.assertEqual(bad_index, 3)
        self.assertIn("hash", reason)

    def test_canonical_hash_format(self):
        # Same string the web app's serializer produces for this block.
        block = {"index": 2, "event": {"confidence": 97.0, "source": "10.0.0.1", "b": [1, 2.5]}, "previous_hash": "x"}
        self.assertEqual(canonical_json(block), '{"event":{"b":[1,2.5],"confidence":97,"source":"10.0.0.1"},"index":2,"previous_hash":"x"}')


class PersistenceTests(unittest.TestCase):
    def test_save_and_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            chain = Blockchain(path)
            chain.add_block({"event_id": "E1"})
            chain.add_block({"event_id": "E2", "confidence": 97.5})
            reloaded = Blockchain(path)
            self.assertEqual(reloaded.chain, chain.chain)
            self.assertTrue(reloaded.verify_chain())
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["chain.json"])  # no temp files left

    def test_tamper_detected_after_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            chain = Blockchain(path)
            for i in range(3):
                chain.add_block({"event_id": f"E{i}", "severity": "High"})
            data = json.loads(path.read_text())
            data[2]["event"]["severity"] = "Low"
            path.write_text(json.dumps(data))
            with self.assertRaises(ChainIntegrityError) as caught:
                Blockchain(path)
            self.assertEqual(caught.exception.bad_index, 3)
            lenient = Blockchain(path, strict=False)
            self.assertEqual(lenient.integrity[:2], (False, 3))

    def test_concurrent_appends_keep_chain_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            chain = Blockchain(path)
            threads = [threading.Thread(target=lambda n=n: [chain.add_block({"t": n, "i": i}) for i in range(10)]) for n in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(chain.chain), 81)
            self.assertTrue(chain.verify_chain())
            self.assertTrue(Blockchain(path).verify_chain())


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

    def test_synthetic_dataset_shape(self):
        df = generate_synthetic_dataset(500, seed=1)
        self.assertEqual(len(df), 500)
        self.assertEqual(set(df["label"].unique()), {0, 1})
        self.assertIn("attack_cat", df.columns)

    def test_official_test_set_metrics_and_web_export_parity(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            generate_synthetic_dataset(1500, seed=3).to_csv(directory / "train.csv", index=False)
            test_df = generate_synthetic_dataset(400, seed=4)
            test_df.to_csv(directory / "test.csv", index=False)
            with contextlib.redirect_stdout(io.StringIO()):
                model = train(directory / "train.csv", directory / "model.pkl", directory / "test.csv", web_export_dir=directory / "web")
            metrics = json.loads((directory / "metrics.json").read_text())
            self.assertTrue(metrics["evaluation"].startswith("official testing set"))
            self.assertEqual(metrics["test_rows"], 400)
            self.assertNotIn("label", metrics["features"])
            self.assertNotIn("attack_cat", metrics["features"])
            for name in ["Random Forest", "Logistic Regression", "Naive Bayes"]:
                self.assertEqual(set(metrics["models"][name]), {"accuracy", "precision", "recall", "f1", "confusion_matrix"})
            # Parity: the exported JSON model scores 5 inputs exactly like the pickle.
            web = WebModel.load(directory / "web" / "web-model.json")
            X, _ = prepare_features(test_df)
            sample = X.head(5)
            expected = model.predict_proba(sample)[:, 1]
            for (_, row), probability in zip(sample.iterrows(), expected):
                features = {k: (None if pd.isna(v) else v) for k, v in row.items()}
                self.assertAlmostEqual(web.predict_proba(features), float(probability), places=9)


if __name__ == "__main__":
    unittest.main()
