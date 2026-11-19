import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import joblib
import pandas as pd
from fastapi.testclient import TestClient

from api import create_app, severity_for
from train_model import generate_synthetic_dataset, prepare_features, train


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        generate_synthetic_dataset(1500, seed=21).to_csv(cls.dir / "train.csv", index=False)
        cls.test_df = generate_synthetic_dataset(300, seed=22)
        cls.test_df.to_csv(cls.dir / "test.csv", index=False)
        with contextlib.redirect_stdout(io.StringIO()):
            train(cls.dir / "train.csv", cls.dir / "model.pkl", cls.dir / "test.csv")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def make_client(self, name="chain.json", model=True):
        app = create_app(
            model_path=self.dir / ("model.pkl" if model else "missing.pkl"),
            metrics_path=self.dir / "metrics.json",
            chain_path=self.dir / name,
            predictions_path=self.dir / f"{name}.predictions.jsonl",
            test_dataset_path=self.dir / "test.csv",
        )
        return TestClient(app)

    def sample_features(self, n=5):
        X, _ = prepare_features(self.test_df)
        return [{k: (None if pd.isna(v) else (v.item() if hasattr(v, "item") else v)) for k, v in row.items()}
                for _, row in X.head(n).iterrows()]

    def test_severity_mapping(self):
        self.assertEqual([severity_for(p) for p in [0.95, 0.949, 0.8, 0.5, 0.499]],
                         ["Critical", "High", "High", "Medium", "Low"])

    def test_predict_parity_with_local_model(self):
        client = self.make_client("parity.json")
        model = joblib.load(self.dir / "model.pkl")
        for features in self.sample_features(5):
            local = float(model.predict_proba(pd.DataFrame([features]))[0][1])
            response = client.post("/api/predict", json={"features": features})
            self.assertEqual(response.status_code, 200, response.text)
            body = response.json()
            self.assertAlmostEqual(body["probability"], round(local, 4), places=4)
            self.assertEqual(body["label"], "Attack" if local >= 0.5 else "Normal")
            self.assertEqual(body["severity"], severity_for(local))
            self.assertEqual(body["recorded"], local >= 0.5)

    def test_predict_validation_errors(self):
        client = self.make_client("validation.json")
        self.assertEqual(client.post("/api/predict", json={"features": {}}).status_code, 422)
        self.assertEqual(client.post("/api/predict", json={"features": {"not_a_feature": 1}}).status_code, 422)
        self.assertEqual(client.post("/api/predict", json={"features": {"sbytes": "lots"}}).status_code, 422)
        self.assertEqual(client.post("/api/predict", json={"nope": 1}).status_code, 422)

    def test_predict_without_model_returns_503(self):
        client = self.make_client("nomodel.json", model=False)
        response = client.post("/api/predict", json={"features": {"sbytes": 10}})
        self.assertEqual(response.status_code, 503)
        self.assertIn("not trained", response.json()["detail"])

    def test_simulate_incidents_metrics_and_chain(self):
        client = self.make_client("flow.json")
        self.assertEqual(client.post("/api/simulate", json={"count": 21}).status_code, 422)
        result = client.post("/api/simulate", json={"count": 20}).json()
        self.assertEqual(result["processed"], 20)
        incidents = client.get("/api/incidents", params={"page_size": 5}).json()
        self.assertEqual(incidents["total"], result["attacks"])
        self.assertLessEqual(len(incidents["items"]), 5)
        if len(incidents["items"]) > 1:
            self.assertGreater(incidents["items"][0]["block_index"], incidents["items"][1]["block_index"])
        for item in client.get("/api/incidents", params={"severity": "Critical"}).json()["items"]:
            self.assertEqual(item["severity"], "Critical")
        metrics = client.get("/api/metrics").json()
        self.assertEqual(metrics["events_analyzed"], 20)
        self.assertEqual(metrics["threats_detected"], result["attacks"])
        self.assertEqual(sum(b["events"] for b in metrics["traffic"]), 20)
        self.assertIsNotNone(metrics["model"]["models"]["Random Forest"]["f1"])
        chain = client.get("/api/chain").json()
        self.assertEqual(chain["length"], result["attacks"] + 1)
        self.assertEqual(client.get("/api/chain/verify").json(), {"valid": True, "length": chain["length"], "bad_index": None, "reason": None})

    def test_tampered_chain_reported_after_restart(self):
        client = self.make_client("tamper.json")
        client.post("/api/simulate", json={"count": 20})
        path = self.dir / "tamper.json"
        data = json.loads(path.read_text())
        self.assertGreater(len(data), 2)
        data[1]["event"]["severity"] = "Low"
        path.write_text(json.dumps(data))
        restarted = self.make_client("tamper.json")
        verify = restarted.get("/api/chain/verify").json()
        self.assertFalse(verify["valid"])
        self.assertEqual(verify["bad_index"], 2)


if __name__ == "__main__":
    unittest.main()
