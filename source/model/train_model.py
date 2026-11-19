import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer, make_column_selector
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

HERE = Path(__file__).resolve().parent
DATA_DIR = HERE / "data"
OFFICIAL_TRAIN = DATA_DIR / "UNSW_NB15_training-set.csv"
OFFICIAL_TEST = DATA_DIR / "UNSW_NB15_testing-set.csv"
SYNTHETIC_TRAIN = DATA_DIR / "synthetic_training-set.csv"
SYNTHETIC_TEST = DATA_DIR / "synthetic_testing-set.csv"
# Columns that reveal the target or identify rows; never used as features.
EXCLUDED_COLUMNS = ["label", "attack_cat", "id"]
MAX_MODEL_MB = 40


def prepare_features(df):
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")
    y = pd.to_numeric(df["label"], errors="raise")
    if y.isna().any() or set(y.unique()) != {0, 1}:
        raise ValueError("Labels must contain both binary classes, 0 and 1, without missing values.")
    if y.value_counts().min() < 2:
        raise ValueError("Each class needs at least two samples for a stratified split.")
    # attack_cat reveals the target; id is a row identifier, not a traffic feature.
    X = df.drop(columns=EXCLUDED_COLUMNS, errors="ignore")
    if X.shape[1] == 0:
        raise ValueError("Dataset has no usable feature columns.")
    return X, y.astype(int)


def build_pipeline(classifier):
    numeric = Pipeline([
        ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
        ("scale", StandardScaler()),
    ])
    categorical = Pipeline([
        ("impute", SimpleImputer(strategy="most_frequent", keep_empty_features=True)),
        ("encode", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])
    preprocess = ColumnTransformer([
        ("numeric", numeric, make_column_selector(dtype_include="number")),
        ("categorical", categorical, make_column_selector(dtype_exclude="number")),
    ])
    return Pipeline([("preprocess", preprocess), ("classifier", classifier)])


# ---------------------------------------------------------------------------
# Synthetic UNSW-NB15-style data (for demos only; not real network traffic)
# ---------------------------------------------------------------------------
ATTACK_PROFILES = {
    # category: (share of attacks, proto weights, service weights, state weights, traits)
    "Generic": (0.30, {"udp": 0.8, "tcp": 0.2}, {"dns": 0.85, "-": 0.15}, {"INT": 0.9, "CON": 0.1},
                {"dur": 0.00001, "spkts": 2, "dpkts": 0, "sbytes": 114, "dbytes": 0, "sttl": 254, "dttl": 0, "ct_srv_src": 28}),
    "Exploits": (0.25, {"tcp": 0.9, "udp": 0.1}, {"http": 0.5, "-": 0.3, "ftp": 0.2}, {"FIN": 0.7, "INT": 0.3},
                 {"dur": 0.9, "spkts": 18, "dpkts": 14, "sbytes": 2800, "dbytes": 1500, "sttl": 62, "dttl": 252, "ct_srv_src": 6}),
    "Fuzzers": (0.15, {"tcp": 0.6, "udp": 0.4}, {"-": 0.7, "http": 0.3}, {"INT": 0.6, "FIN": 0.4},
                {"dur": 0.4, "spkts": 8, "dpkts": 2, "sbytes": 900, "dbytes": 200, "sttl": 254, "dttl": 0, "ct_srv_src": 4}),
    "DoS": (0.12, {"tcp": 0.7, "udp": 0.3}, {"http": 0.4, "-": 0.6}, {"INT": 0.5, "FIN": 0.5},
            {"dur": 0.3, "spkts": 40, "dpkts": 2, "sbytes": 12000, "dbytes": 300, "sttl": 254, "dttl": 252, "ct_srv_src": 18}),
    "Reconnaissance": (0.10, {"tcp": 0.5, "udp": 0.3, "icmp": 0.2}, {"-": 0.9, "dns": 0.1}, {"INT": 0.8, "REQ": 0.2},
                       {"dur": 0.00002, "spkts": 2, "dpkts": 0, "sbytes": 200, "dbytes": 0, "sttl": 254, "dttl": 0, "ct_srv_src": 12}),
    "Backdoor": (0.04, {"tcp": 1.0}, {"-": 1.0}, {"INT": 0.6, "FIN": 0.4},
                 {"dur": 0.5, "spkts": 10, "dpkts": 6, "sbytes": 1100, "dbytes": 500, "sttl": 254, "dttl": 252, "ct_srv_src": 3}),
    "Shellcode": (0.04, {"tcp": 0.8, "udp": 0.2}, {"-": 1.0}, {"INT": 1.0},
                  {"dur": 0.1, "spkts": 4, "dpkts": 2, "sbytes": 700, "dbytes": 100, "sttl": 254, "dttl": 0, "ct_srv_src": 2}),
}
NORMAL_PROFILE = ({"tcp": 0.75, "udp": 0.2, "icmp": 0.05}, {"http": 0.35, "-": 0.3, "dns": 0.2, "smtp": 0.08, "ftp": 0.07},
                  {"FIN": 0.6, "CON": 0.3, "INT": 0.1},
                  {"dur": 1.2, "spkts": 24, "dpkts": 26, "sbytes": 3200, "dbytes": 18000, "sttl": 31, "dttl": 29, "ct_srv_src": 5})


def _pick(rng, weights, size):
    keys = list(weights)
    probs = np.array([weights[k] for k in keys], dtype=float)
    return rng.choice(keys, size=size, p=probs / probs.sum())


def _profile_rows(rng, n, protos, services, states, traits):
    noise = lambda scale: rng.lognormal(mean=0.0, sigma=scale, size=n)  # noqa: E731
    dur = traits["dur"] * noise(0.9)
    spkts = np.maximum(1, np.round(traits["spkts"] * noise(0.6))).astype(int)
    dpkts = np.maximum(0, np.round(traits["dpkts"] * noise(0.6))).astype(int)
    sbytes = np.maximum(28, np.round(traits["sbytes"] * noise(0.7))).astype(int)
    dbytes = np.maximum(0, np.round(traits["dbytes"] * noise(0.8))).astype(int)
    # TTLs mostly follow the profile but sometimes take another typical value.
    ttl_values = np.array([0, 29, 31, 62, 252, 254])
    sttl = np.where(rng.random(n) < 0.85, traits["sttl"], rng.choice(ttl_values, n))
    dttl = np.where(rng.random(n) < 0.85, traits["dttl"], rng.choice(ttl_values, n))
    safe_dur = np.maximum(dur, 1e-6)
    return pd.DataFrame({
        "dur": np.round(dur, 6),
        "proto": _pick(rng, protos, n),
        "service": _pick(rng, services, n),
        "state": _pick(rng, states, n),
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": np.round((spkts + dpkts) / safe_dur, 3),
        "sttl": sttl,
        "dttl": dttl,
        "sload": np.round(sbytes * 8 / safe_dur, 3),
        "dload": np.round(dbytes * 8 / safe_dur, 3),
        "smean": np.round(sbytes / spkts).astype(int),
        "dmean": np.round(np.divide(dbytes, np.maximum(dpkts, 1))).astype(int),
        "ct_srv_src": np.maximum(1, np.round(traits["ct_srv_src"] * noise(0.5))).astype(int),
        "ct_dst_ltm": np.maximum(1, np.round(rng.gamma(2.0, 2.0, n))).astype(int),
    })


def generate_synthetic_dataset(rows=6000, attack_share=0.55, seed=42):
    """Build a small UNSW-NB15-shaped dataset with overlapping classes and label noise."""
    rng = np.random.default_rng(seed)
    n_attack = int(rows * attack_share)
    n_normal = rows - n_attack
    parts = [_profile_rows(rng, n_normal, *NORMAL_PROFILE).assign(attack_cat="Normal", label=0)]
    shares = np.array([p[0] for p in ATTACK_PROFILES.values()])
    counts = rng.multinomial(n_attack, shares / shares.sum())
    for (category, (_, protos, services, states, traits)), count in zip(ATTACK_PROFILES.items(), counts):
        if count:
            parts.append(_profile_rows(rng, count, protos, services, states, traits).assign(attack_cat=category, label=1))
    df = pd.concat(parts, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    # ~3% of labels flipped and ~1% of values missing so the task is not trivially separable.
    flip = rng.random(len(df)) < 0.03
    df.loc[flip, "label"] = 1 - df.loc[flip, "label"]
    for column in ["dur", "sbytes", "service"]:
        df.loc[rng.random(len(df)) < 0.01, column] = np.nan
    df.insert(0, "id", np.arange(1, len(df) + 1))
    return df


def write_synthetic_datasets(train_path=SYNTHETIC_TRAIN, test_path=SYNTHETIC_TEST, train_rows=6000, test_rows=2000):
    train_path.parent.mkdir(parents=True, exist_ok=True)
    generate_synthetic_dataset(train_rows, seed=42).to_csv(train_path, index=False)
    generate_synthetic_dataset(test_rows, seed=7).to_csv(test_path, index=False)
    return train_path, test_path


# ---------------------------------------------------------------------------
# Training, evaluation, metrics and web export
# ---------------------------------------------------------------------------
def model_metrics(y_true, prediction):
    return {
        "accuracy": round(float(accuracy_score(y_true, prediction)), 4),
        "precision": round(float(precision_score(y_true, prediction, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, prediction, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, prediction, zero_division=0)), 4),
        "confusion_matrix": confusion_matrix(y_true, prediction, labels=[0, 1]).tolist(),
    }


def print_comparison(results):
    header = f"{'Model':<22}{'Accuracy':>10}{'Precision':>11}{'Recall':>9}{'F1':>8}"
    print("\n" + header)
    print("-" * len(header))
    for name, m in results.items():
        print(f"{name:<22}{m['accuracy']:>10.4f}{m['precision']:>11.4f}{m['recall']:>9.4f}{m['f1']:>8.4f}")


def feature_importances(model, top=None):
    """Random Forest importances summed back onto the original columns (one-hot parts combined)."""
    preprocess = model.named_steps["preprocess"]
    forest = model.named_steps["classifier"]
    names = []
    for name, transformer, columns in preprocess.transformers_:
        if name == "numeric":
            names.extend(list(columns))
        elif name == "categorical":
            for column, categories in zip(columns, transformer.named_steps["encode"].categories_):
                names.extend([column] * len(categories))
    totals = {}
    for column, value in zip(names, forest.feature_importances_):
        totals[column] = totals.get(column, 0.0) + float(value)
    ranked = sorted(totals.items(), key=lambda item: item[1], reverse=True)
    return [{"feature": f, "importance": round(v, 6)} for f, v in ranked[:top]]


def export_web_model(model, path, metadata):
    """Write the fitted Random Forest pipeline as JSON so the web app can score
    records without Python. Trees compare float32-cast values, like sklearn."""
    preprocess = model.named_steps["preprocess"]
    forest = model.named_steps["classifier"]
    numeric_columns, categorical_columns = [], []
    numeric = categorical = None
    for name, transformer, columns in preprocess.transformers_:
        if name == "numeric":
            numeric_columns, numeric = list(columns), transformer
        elif name == "categorical":
            categorical_columns, categorical = list(columns), transformer
    trees = []
    for estimator in forest.estimators_:
        tree = estimator.tree_
        values = tree.value[:, 0, :]
        totals = values.sum(axis=1)
        positive = np.divide(values[:, 1], totals, out=np.zeros_like(totals), where=totals > 0)
        trees.append({
            "left": tree.children_left.tolist(),
            "right": tree.children_right.tolist(),
            "feature": tree.feature.tolist(),
            "threshold": [float(t) for t in tree.threshold],
            "probability": [float(p) for p in positive],
        })
    bundle = {
        **metadata,
        "classes": [int(c) for c in forest.classes_],
        "numeric": {
            "columns": numeric_columns,
            "medians": numeric.named_steps["impute"].statistics_.tolist() if numeric is not None else [],
            "means": numeric.named_steps["scale"].mean_.tolist() if numeric is not None else [],
            "scales": numeric.named_steps["scale"].scale_.tolist() if numeric is not None else [],
        },
        "categorical": {
            "columns": categorical_columns,
            "most_frequent": [str(v) for v in categorical.named_steps["impute"].statistics_] if categorical is not None else [],
            "categories": [[str(v) for v in c] for c in categorical.named_steps["encode"].categories_] if categorical is not None else [],
        },
        "trees": trees,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, separators=(",", ":")))
    return path


def export_simulation_rows(model, X_test, test_df, path, rows=300, seed=11):
    """Sample test rows (features + category + the Python model's probability)
    for the web app's simulation and for cross-language parity tests."""
    sample = X_test.sample(n=min(rows, len(X_test)), random_state=seed)
    probabilities = model.predict_proba(sample)[:, 1]
    categories = test_df.loc[sample.index, "attack_cat"] if "attack_cat" in test_df else pd.Series("Unknown", index=sample.index)
    records = []
    for (index, row), probability in zip(sample.iterrows(), probabilities):
        features = {k: (None if pd.isna(v) else (v.item() if hasattr(v, "item") else v)) for k, v in row.items()}
        records.append({"features": features, "category": str(categories[index]), "expected_probability": float(probability)})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, separators=(",", ":")))
    return path


def train(dataset_path, output_path, test_dataset_path=None, metrics_path=None, web_export_dir=None):
    output_path = Path(output_path)
    df = pd.read_csv(dataset_path)
    X, y = prepare_features(df)
    print("Training dataset loaded:", df.shape)
    print("Features shape:", X.shape)
    print("Target shape:", y.shape)
    if test_dataset_path:
        test_df = pd.read_csv(test_dataset_path)
        X_test, y_test = prepare_features(test_df)
        missing = [c for c in X.columns if c not in X_test.columns]
        if missing:
            raise ValueError(f"Testing set is missing feature columns: {', '.join(missing)}")
        X_test = X_test[list(X.columns)]
        X_train, y_train = X, y
        evaluation = f"official testing set ({Path(test_dataset_path).name})"
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        test_df = df.loc[X_test.index]
        evaluation = "stratified 80/20 holdout split"
    print("Training data:", X_train.shape)
    print("Testing data:", X_test.shape, "-", evaluation)

    #model1 (sized so the exported web model stays small)
    rf = build_pipeline(RandomForestClassifier(n_estimators=50, max_depth=12, min_samples_leaf=3, random_state=42, n_jobs=-1))
    #model2
    lr = build_pipeline(LogisticRegression(max_iter=1000, random_state=42))
    #model3
    nb = build_pipeline(GaussianNB())
    results = {}
    for name, model in [("Random Forest", rf), ("Logistic Regression", lr), ("Naive Bayes", nb)]:
        model.fit(X_train, y_train)
        prediction = model.predict(X_test)
        results[name] = model_metrics(y_test, prediction)
        print(f"\n{name} Accuracy: {results[name]['accuracy']:.4f}")
        print(classification_report(y_test, prediction, zero_division=0))
    print_comparison(results)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, output_path)
    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"\nModel file size: {size_mb:.2f} MB")
    if size_mb > MAX_MODEL_MB:
        raise ValueError(f"Model file is {size_mb:.1f} MB, above the {MAX_MODEL_MB} MB limit; reduce n_estimators or max_depth.")
    trained_at = datetime.now(timezone.utc)
    metrics = {
        "model_version": f"rf-{trained_at.strftime('%Y%m%d%H%M%S')}",
        "selected_model": "Random Forest",
        "trained_at": trained_at.isoformat(),
        "dataset": Path(dataset_path).name,
        "dataset_kind": "synthetic" if "synthetic" in Path(dataset_path).name else "real",
        "artifact_bytes": output_path.stat().st_size,
        "feature_importances": feature_importances(rf, top=10),
        "evaluation": evaluation,
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "features": list(X.columns),
        "models": results,
    }
    metrics_path = Path(metrics_path) if metrics_path else output_path.with_name("metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2))
    print("\nRandom Forest model and preprocessing saved:", output_path)
    print("Metrics saved:", metrics_path)
    if web_export_dir:
        web_export_dir = Path(web_export_dir)
        web_path = web_export_dir / "web-model.json"
        export_web_model(rf, web_path, {
            "model_version": metrics["model_version"], "features": metrics["features"], "metrics": metrics,
        })
        # Record the web artifact size inside its own metrics, then rewrite once.
        metrics["web_artifact_bytes"] = web_path.stat().st_size
        export_web_model(rf, web_path, {
            "model_version": metrics["model_version"], "features": metrics["features"], "metrics": metrics,
        })
        metrics_path.write_text(json.dumps(metrics, indent=2))
        export_simulation_rows(rf, X_test, test_df, web_export_dir / "simulation-rows.json")
        web_size = (web_export_dir / "web-model.json").stat().st_size / (1024 * 1024)
        print(f"Web model exported: {web_export_dir} ({web_size:.2f} MB)")
    print("Sample Prediction:", rf.predict(X_test.iloc[0:1])[0])
    return rf


def main():
    parser = argparse.ArgumentParser(description="Train UNSW-NB15 threat detection models.")
    parser.add_argument("--dataset", type=Path, default=None, help="Training CSV (default: data/UNSW_NB15_training-set.csv).")
    parser.add_argument("--test-dataset", type=Path, default=None, help="Testing CSV (default: the official testing set when present).")
    parser.add_argument("--synthetic", action="store_true", help="Generate and use a small synthetic dataset instead of UNSW-NB15.")
    parser.add_argument("--output", type=Path, default=HERE / "random_forest_model.pkl")
    parser.add_argument("--metrics", type=Path, default=None, help="Metrics JSON path (default: metrics.json next to the model).")
    parser.add_argument("--export-web", type=Path, default=None, help="Folder for the web app's JSON model and simulation rows.")
    args = parser.parse_args()
    if args.synthetic:
        dataset, test_dataset = write_synthetic_datasets()
        print("Synthetic datasets written:", dataset, test_dataset)
        dataset = args.dataset or dataset
        test_dataset = args.test_dataset or test_dataset
    else:
        dataset = args.dataset or OFFICIAL_TRAIN
        test_dataset = args.test_dataset or (OFFICIAL_TEST if OFFICIAL_TEST.is_file() else None)
        if not dataset.is_file():
            parser.error(f"Dataset not found: {dataset}. See download_dataset.md, pass --dataset, or use --synthetic.")
    if test_dataset is not None and not Path(test_dataset).is_file():
        parser.error(f"Testing dataset not found: {test_dataset}")
    try:
        train(dataset, args.output, test_dataset, args.metrics, args.export_web)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Training failed: {error}\n")


if __name__ == "__main__":
    main()
