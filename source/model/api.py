"""FastAPI service: scores traffic records and records detections on the hash chain.

Run with:  uvicorn api:app --port 8000   (from source/model)
Paths are configurable with environment variables; see .env.example.
"""

import json
import os
import random
import threading
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional, Union

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from blockchain import Blockchain
from train_model import EXCLUDED_COLUMNS, OFFICIAL_TEST, SYNTHETIC_TEST

HERE = Path(__file__).resolve().parent
SEVERITIES = ["Critical", "High", "Medium", "Low"]
MAX_BLOCKS = int(os.environ.get("MAX_BLOCKS", "5000"))
MAX_SIMULATE = 20
FeatureValue = Union[float, int, str, None]


def severity_for(probability):
    """Severity of an attack probability: Critical >=0.95, High >=0.8, Medium >=0.5, else Low."""
    if probability >= 0.95:
        return "Critical"
    if probability >= 0.8:
        return "High"
    if probability >= 0.5:
        return "Medium"
    return "Low"


class PredictRequest(BaseModel):
    features: dict[str, FeatureValue] = Field(..., description="One traffic record keyed by feature name.")
    source: Optional[str] = Field(None, max_length=64)
    category: Optional[str] = Field(None, max_length=64)

    @field_validator("features")
    @classmethod
    def not_empty(cls, value):
        if not value:
            raise ValueError("features must contain at least one value")
        if len(value) > 200:
            raise ValueError("too many features")
        return value


class SimulateRequest(BaseModel):
    count: int = Field(10, ge=1, le=MAX_SIMULATE)


class StatusChangeRequest(BaseModel):
    status: Literal["Open", "Contained"]
    by: str = Field("Security team", min_length=1, max_length=40)


def _env_path(name, default):
    value = os.environ.get(name)
    return Path(value) if value else default


class Service:
    def __init__(self, model_path, metrics_path, chain_path, predictions_path, test_dataset_path):
        self.model_path = Path(model_path)
        self.metrics_path = Path(metrics_path)
        self.predictions_path = Path(predictions_path)
        self.test_dataset_path = Path(test_dataset_path) if test_dataset_path else None
        self.chain = Blockchain(chain_path, strict=False)
        ok, bad_index, reason = self.chain.integrity
        if not ok:
            print(f"WARNING: chain at {chain_path} failed verification at block {bad_index}: {reason}")
        self._model = None
        self._model_mtime = None
        self._lock = threading.Lock()
        self._test_rows = None

    # -- model -------------------------------------------------------------
    def model(self):
        if not self.model_path.is_file():
            raise HTTPException(503, "Model not trained yet. Run: python train_model.py --synthetic")
        mtime = self.model_path.stat().st_mtime
        with self._lock:
            if self._model is None or mtime != self._model_mtime:
                self._model = joblib.load(self.model_path)
                self._model_mtime = mtime
            return self._model

    def metrics(self):
        if not self.metrics_path.is_file():
            return None
        return json.loads(self.metrics_path.read_text())

    def model_version(self):
        metrics = self.metrics()
        return metrics.get("model_version", "unknown") if metrics else "unknown"

    # -- prediction --------------------------------------------------------
    def predict(self, features, source=None, category=None):
        model = self.model()
        expected = list(model.feature_names_in_)
        clean = {k: v for k, v in features.items() if k not in EXCLUDED_COLUMNS}
        unknown = sorted(set(clean) - set(expected))
        if unknown:
            raise HTTPException(422, f"Unknown feature(s): {', '.join(unknown)}")
        if not clean:
            raise HTTPException(422, "No model features supplied.")
        record = {}
        for name in expected:
            value = clean.get(name)
            if model_column_is_numeric(model, name):
                if isinstance(value, str):
                    try:
                        value = float(value)
                    except ValueError:
                        raise HTTPException(422, f"Feature '{name}' must be a number.")
                record[name] = float("nan") if value is None else float(value)
            else:
                record[name] = None if value is None else str(value)
        row = pd.DataFrame([record])
        probability = float(model.predict_proba(row)[0][list(model.classes_).index(1)])
        is_attack = probability >= 0.5
        severity = severity_for(probability)
        result = {
            "label": "Attack" if is_attack else "Normal",
            "is_attack": is_attack,
            "probability": round(probability, 4),
            "severity": severity,
            "recorded": False,
            "block_index": None,
        }
        self._log_prediction(is_attack, probability)
        if is_attack:
            if len(self.chain.chain) >= MAX_BLOCKS:
                raise HTTPException(429, f"The ledger is full ({MAX_BLOCKS} blocks). Archive chain.json to record more.")
            block = self.chain.add_block({
                "type": "detection",
                "event_id": f"SIG-{uuid.uuid4().hex[:8].upper()}",
                "source": source or "unknown",
                "category": category or "Unclassified",
                "severity": severity,
                "confidence": round(probability * 100, 2),
                "model_version": self.model_version(),
                "status": "Open",
            })
            result.update(recorded=True, block_index=block["index"])
        return result

    def _log_prediction(self, is_attack, probability):
        line = json.dumps({"t": datetime.now(timezone.utc).isoformat(), "attack": is_attack, "p": round(probability, 4)})
        self.predictions_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, open(self.predictions_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def predictions(self):
        if not self.predictions_path.is_file():
            return []
        rows = []
        for line in self.predictions_path.read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows

    # -- chain views -------------------------------------------------------
    def incidents(self):
        latest_status = {}
        for block in self.chain.chain:
            event = block.get("event") if isinstance(block, dict) else None
            if isinstance(event, dict) and event.get("type") == "status_change":
                inc_id = event.get("incident_id")
                if inc_id:
                    latest_status[inc_id] = {
                        "status": event.get("new_status", "Open"),
                        "status_block_index": block["index"],
                        "status_changed_at": block["timestamp"],
                        "status_changed_by": event.get("by", "Security team"),
                    }
        items = []
        for block in reversed(self.chain.chain):
            event = block.get("event") if isinstance(block, dict) else None
            if not isinstance(event, dict) or event.get("type") != "detection":
                continue
            status_info = latest_status.get(event.get("event_id"), {})
            items.append({
                **event,
                "status": status_info.get("status", event.get("status", "Open")),
                "status_block_index": status_info.get("status_block_index"),
                "status_changed_at": status_info.get("status_changed_at"),
                "status_changed_by": status_info.get("status_changed_by"),
                "block_index": block["index"],
                "detected_at": block["timestamp"],
                "hash": block["hash"],
                "previous_hash": block["previous_hash"],
            })
        return items

    def change_incident_status(self, incident_id: str, new_status: str, by: str):
        matches = [i for i in self.incidents() if i.get("event_id") == incident_id]
        if not matches:
            raise HTTPException(404, f"Incident {incident_id} was not found.")
        if matches[0].get("status") == new_status:
            raise HTTPException(409, f"Incident {incident_id} is already {new_status}.")
        if len(self.chain.chain) >= MAX_BLOCKS:
            raise HTTPException(429, f"The ledger is full ({MAX_BLOCKS} blocks).")
        block = self.chain.add_block({
            "type": "status_change",
            "incident_id": incident_id,
            "new_status": new_status,
            "by": by,
        })
        return {"ok": True, "block_index": block["index"], "status": new_status}

    def model_health(self):
        metrics = self.metrics() or {}
        predictions = self.predictions()
        now = datetime.now(timezone.utc)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        one_hour_ago = now - timedelta(hours=1)
        twenty_five_hours_ago = now - timedelta(hours=25)
        today_n = today_attacks = recent_n = recent_attacks = earlier_n = earlier_attacks = 0
        attack_prob_sum = 0.0
        for row in predictions:
            try:
                moment = datetime.fromisoformat(row["t"])
            except (KeyError, ValueError):
                continue
            is_attack = bool(row.get("attack"))
            if moment >= day_start:
                today_n += 1
                if is_attack:
                    today_attacks += 1
                    attack_prob_sum += float(row.get("p", 0.0))
            if moment >= one_hour_ago:
                recent_n += 1
                if is_attack:
                    recent_attacks += 1
            elif moment >= twenty_five_hours_ago:
                earlier_n += 1
                if is_attack:
                    earlier_attacks += 1

        recent_rate = (recent_attacks * 100.0 / recent_n) if recent_n else None
        baseline_rate = (earlier_attacks * 100.0 / earlier_n) if earlier_n else None
        if recent_n < 20 or earlier_n < 20 or recent_rate is None or baseline_rate is None:
            drift = {
                "status": "insufficient",
                "recentRate": recent_rate,
                "baselineRate": baseline_rate,
                "message": "Needs at least 20 predictions in the last hour and in the 24 hours before it.",
            }
        elif abs(recent_rate - baseline_rate) > 20:
            direction = "rose" if recent_rate > baseline_rate else "fell"
            drift = {
                "status": "warning",
                "recentRate": recent_rate,
                "baselineRate": baseline_rate,
                "message": f"Attack rate {direction} from {baseline_rate:.1f}% to {recent_rate:.1f}% in the last hour.",
            }
        else:
            drift = {
                "status": "ok",
                "recentRate": recent_rate,
                "baselineRate": baseline_rate,
                "message": "Attack rate is in line with the earlier average.",
            }

        models = metrics.get("models", {})
        selected = metrics.get("selected_model", "Random Forest")
        artifact_bytes = metrics.get("artifact_bytes")
        if artifact_bytes is None and self.model_path.is_file():
            artifact_bytes = self.model_path.stat().st_size
        return {
            "info": {
                "modelVersion": metrics.get("model_version", "unknown"),
                "selectedModel": selected,
                "evaluation": metrics.get("evaluation", "unknown"),
                "trainedAt": metrics.get("trained_at", ""),
                "features": metrics.get("features", []),
                "scores": models.get(selected),
            },
            "datasetKind": metrics.get("dataset_kind", "synthetic" if "synthetic" in str(metrics.get("dataset", "")) else "real"),
            "dataset": metrics.get("dataset", "unknown"),
            "artifactBytes": artifact_bytes,
            "webArtifactBytes": metrics.get("web_artifact_bytes"),
            "trainRows": metrics.get("train_rows"),
            "testRows": metrics.get("test_rows"),
            "comparison": [
                {"model": name, "accuracy": m["accuracy"], "precision": m["precision"], "recall": m["recall"], "f1": m["f1"]}
                for name, m in models.items()
            ],
            "confusionMatrix": models.get(selected, {}).get("confusion_matrix"),
            "featureImportances": metrics.get("feature_importances", [])[:10],
            "live": {
                "predictionsToday": today_n,
                "attacksToday": today_attacks,
                "attackRateToday": (today_attacks * 100.0 / today_n) if today_n else None,
                "avgAttackConfidence": round((attack_prob_sum / today_attacks) * 100.0, 2) if today_attacks else None,
                "drift": drift,
            },
        }

    def test_rows(self):
        if self._test_rows is None:
            path = self.test_dataset_path
            if path is None or not path.is_file():
                raise HTTPException(503, "No testing dataset found. Run: python train_model.py --synthetic")
            self._test_rows = pd.read_csv(path)
        return self._test_rows


def model_column_is_numeric(model, column):
    preprocess = model.named_steps["preprocess"]
    for name, _, columns in preprocess.transformers_:
        if name == "numeric" and column in list(columns):
            return True
    return False


def traffic_series(predictions, now=None, hours=24, bucket_hours=2):
    now = now or datetime.now(timezone.utc)
    start = (now - timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)
    buckets = []
    for i in range(hours // bucket_hours + 1):
        buckets.append({"time": (start + timedelta(hours=i * bucket_hours)).strftime("%H:%M"), "events": 0, "threats": 0})
    for row in predictions:
        try:
            moment = datetime.fromisoformat(row["t"])
        except (KeyError, ValueError):
            continue
        if moment < start:
            continue
        slot = min(int((moment - start).total_seconds() // (bucket_hours * 3600)), len(buckets) - 1)
        buckets[slot]["events"] += 1
        buckets[slot]["threats"] += 1 if row.get("attack") else 0
    return buckets


def create_app(model_path=None, metrics_path=None, chain_path=None, predictions_path=None, test_dataset_path=None):
    default_test = OFFICIAL_TEST if OFFICIAL_TEST.is_file() else SYNTHETIC_TEST
    service = Service(
        model_path or _env_path("MODEL_PATH", HERE / "random_forest_model.pkl"),
        metrics_path or _env_path("METRICS_PATH", HERE / "metrics.json"),
        chain_path or _env_path("CHAIN_PATH", HERE / "chain.json"),
        predictions_path or _env_path("PREDICTIONS_PATH", HERE / "predictions.jsonl"),
        test_dataset_path or _env_path("TEST_DATASET_PATH", default_test),
    )
    app = FastAPI(title="Sentinel Threat Detection API", version="1.0.0")
    origins = os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080,http://localhost:5173").split(",")
    app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in origins if o.strip()],
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
    app.state.service = service

    @app.post("/api/predict")
    def predict(body: PredictRequest):
        return service.predict(body.features, body.source, body.category)

    @app.get("/api/incidents")
    def incidents(
        severity: Optional[Literal["Critical", "High", "Medium", "Low"]] = None,
        status: Optional[Literal["Open", "Contained"]] = None,
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=200),
    ):
        items = service.incidents()
        if severity:
            items = [i for i in items if i.get("severity") == severity]
        if status:
            items = [i for i in items if i.get("status") == status]
        start = (page - 1) * page_size
        return {"items": items[start:start + page_size], "total": len(items), "page": page, "page_size": page_size}

    @app.get("/api/metrics")
    def metrics():
        incidents = service.incidents()
        predictions = service.predictions()
        counts = Counter(i.get("severity") for i in incidents)
        total = len(incidents)
        avg = round(sum(float(i.get("confidence", 0)) for i in incidents) / total, 2) if total else None
        return {
            "events_analyzed": len(predictions),
            "threats_detected": total,
            "avg_confidence": avg,
            "severity_summary": [{"label": s, "count": counts.get(s, 0),
                                  "percent": round(counts.get(s, 0) * 100 / total) if total else 0} for s in SEVERITIES],
            "model": service.metrics(),
            "traffic": traffic_series(predictions),
        }

    @app.get("/api/chain")
    def chain(limit: int = Query(50, ge=1, le=1000)):
        blocks = list(reversed(service.chain.chain))
        return {"length": len(service.chain.chain), "blocks": blocks[:limit]}

    @app.get("/api/chain/verify")
    def verify():
        ok, bad_index, reason = service.chain.verify_chain_detailed()
        return {"valid": ok, "length": len(service.chain.chain), "bad_index": bad_index, "reason": reason}

    @app.post("/api/simulate")
    def simulate(body: SimulateRequest = SimulateRequest()):
        rows = service.test_rows()
        sample = rows.sample(n=min(body.count, len(rows)), random_state=random.randrange(1 << 30))
        results = []
        for _, row in sample.iterrows():
            features = {k: (None if pd.isna(v) else (v.item() if hasattr(v, "item") else v))
                        for k, v in row.items() if k not in EXCLUDED_COLUMNS}
            category = str(row["attack_cat"]) if "attack_cat" in row and not pd.isna(row["attack_cat"]) else None
            source = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            results.append(service.predict(features, source, category))
        attacks = sum(1 for r in results if r["is_attack"])
        return {"processed": len(results), "attacks": attacks, "normal": len(results) - attacks}

    @app.post("/api/incidents/{incident_id}/status")
    def update_incident_status(incident_id: str, body: StatusChangeRequest):
        return service.change_incident_status(incident_id, body.status, body.by)

    @app.get("/api/model/health")
    def model_health():
        return service.model_health()

    return app


app = create_app()
