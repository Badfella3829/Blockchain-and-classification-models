# Sentinel Threat Intelligence Dashboard

Sentinel is a security dashboard for reviewing threat activity, searching and filtering incidents, inspecting incident details, and exporting incident data as CSV. The dashboard uses sample data; it is not connected to a live threat feed or model service.

The repository also preserves Python utilities for training and evaluating classification models and for recording events in a hash-linked blockchain. These tools are independent of the dashboard.

## Requirements

- [Bun](https://bun.sh/) for the web application
- Python 3.10 or later for the model utilities
- A labeled CSV dataset for model training; no dataset is included

## Run the dashboard

```sh
bun install
bun run dev
```

Open the local address printed by Vite. To run the project's automated checks:

```sh
bun run test
```

## Train the classification models

Install the Python dependencies:

```sh
python -m pip install -r source/model/requirements.txt
```

Provide a CSV with a binary `label` column containing both `0` and `1`, plus one or more usable feature columns. The `label`, `attack_cat`, and `id` columns are excluded from model features to avoid target leakage and row-identifier use. Then run:

```sh
python source/model/train_model.py --dataset /path/to/your-dataset.csv --output random_forest_model.pkl
```

The script evaluates Random Forest, Logistic Regression, and Naive Bayes using a stratified holdout split, then saves the Random Forest preprocessing-and-model pipeline. Keep the output model file private if your dataset contains sensitive information.

## Blockchain example

Run the standalone example with:

```sh
python source/model/blockchain.py
```

The example creates a genesis block, records two sample events, and checks the chain's hashes and links. It is an educational integrity demonstration, not a distributed or production blockchain service.

## Project structure

- `src/components/threat-dashboard/` — dashboard interface and sample data
- `src/routes/` — application routes
- `source/model/` — Python training and blockchain utilities
