import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer, make_column_selector
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


def prepare_features(df):
    if "label" not in df.columns:
        raise ValueError("Dataset must contain a 'label' column.")
    y = pd.to_numeric(df["label"], errors="raise")
    if y.isna().any() or set(y.unique()) != {0, 1}:
        raise ValueError("Labels must contain both binary classes, 0 and 1, without missing values.")
    if y.value_counts().min() < 2:
        raise ValueError("Each class needs at least two samples for a stratified split.")
    # attack_cat reveals the target; id is a row identifier, not a traffic feature.
    X = df.drop(columns=["label", "attack_cat", "id"], errors="ignore")
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


def train(dataset_path, output_path):
    df = pd.read_csv(dataset_path)
    X, y = prepare_features(df)
    print("Training dataset loaded:", df.shape)
    print("Features shape:", X.shape)
    print("Target shape:", y.shape)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print("Training data:", X_train.shape)
    print("Testing data:", X_test.shape)

    #model1
    rf = build_pipeline(RandomForestClassifier(n_estimators=100, random_state=42))
    #model2
    lr = build_pipeline(LogisticRegression(max_iter=1000, random_state=42))
    #model3
    nb = build_pipeline(GaussianNB())
    for name, model in [("Random Forest", rf), ("Logistic Regression", lr), ("Naive Bayes", nb)]:
        model.fit(X_train, y_train)
        prediction = model.predict(X_test)
        print(f"\n{name} Accuracy: {accuracy_score(y_test, prediction):.4f}")
        print(classification_report(y_test, prediction, zero_division=0))

    joblib.dump(rf, output_path)
    print("Random Forest model and preprocessing saved:", output_path)
    print("Sample Prediction:", rf.predict(X_test.iloc[0:1])[0])
    return rf


def main():
    parser = argparse.ArgumentParser(description="Train UNSW-NB15 threat detection models.")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).resolve().parent / "dataset.csv" / "UNSW_NB15_training-set.csv")
    parser.add_argument("--output", type=Path, default=Path("random_forest_model.pkl"))
    args = parser.parse_args()
    if not args.dataset.is_file():
        parser.error(f"Dataset not found: {args.dataset}. Supply the CSV using --dataset.")
    try:
        train(args.dataset, args.output)
    except (ValueError, OSError) as error:
        parser.exit(1, f"Training failed: {error}\n")


if __name__ == "__main__":
    main()
