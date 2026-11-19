"""Score records with the JSON model exported by ``train_model.py --export-web``.

Pure Python + NumPy (no scikit-learn), mirroring the web app's TypeScript
scorer so both can be checked against the original pipeline."""

import json
import math
from pathlib import Path

import numpy as np


class WebModel:
    def __init__(self, bundle):
        self.bundle = bundle
        self.model_version = bundle.get("model_version", "unknown")
        self.features = bundle["features"]

    @classmethod
    def load(cls, path):
        return cls(json.loads(Path(path).read_text()))

    def vectorize(self, features):
        numeric = self.bundle["numeric"]
        categorical = self.bundle["categorical"]
        vector = []
        for column, median, mean, scale in zip(numeric["columns"], numeric["medians"], numeric["means"], numeric["scales"]):
            value = features.get(column)
            if value is None or (isinstance(value, float) and math.isnan(value)):
                value = median
            vector.append((float(value) - mean) / scale)
        for column, fallback, categories in zip(categorical["columns"], categorical["most_frequent"], categorical["categories"]):
            value = features.get(column)
            value = fallback if value is None or (isinstance(value, float) and math.isnan(value)) else str(value)
            vector.extend(1.0 if value == category else 0.0 for category in categories)
        # Trees compare float32 values, as scikit-learn does.
        return np.asarray(vector, dtype=np.float32)

    def predict_proba(self, features):
        x = self.vectorize(features)
        total = 0.0
        for tree in self.bundle["trees"]:
            node = 0
            left, right = tree["left"], tree["right"]
            while left[node] != -1:
                node = left[node] if x[tree["feature"][node]] <= tree["threshold"][node] else right[node]
            total += tree["probability"][node]
        return total / len(self.bundle["trees"])
