# Sentinel — AI Threat Detection & Tamper-Evident Audit Ledger

**Author:** Akansh Chahal

Sentinel is a real-time network threat detection dashboard paired with an append-only, SHA-256 hash-linked audit ledger and an interpretable Random Forest classifier trained on UNSW-NB15-style network flow features.

## Features

- **Multi-view Hash Navigation (`#overview`, `#detections`, `#audit`, `#model-health`)**:
  - **Overview (`#overview`)**: Live KPI cards (total events, attacks detected, critical open incidents, chain status), 24-hour traffic & threat signal chart, severity breakdown, and latest 5 incidents.
  - **Detections (`#detections`)**: Full searchable, filterable (severity & status), sortable, paginated incident table, bulk containment actions, filtered CSV export, and a slide-over detail drawer showing full flow metadata, model confidence, and cryptographic block proof.
  - **Audit Ledger (`#audit`)**: Newest-first paginated view of every block on the hash chain with expandable raw JSON inspection, copy-hash buttons, full-chain JSON export, and cryptographic integrity verification highlighting any tampered block index.
  - **Model Health (`#model-health`)**: Model version, trained-at timestamp, dataset provenance, artifact size, 3-model comparison chart (Random Forest, Logistic Regression, Naive Bayes), deployed confusion matrix, top-10 Random Forest feature importances, and live attack-rate drift monitoring.
- **Interactive Flow Analyzer**: Score custom or preset network flows live against the deployed Random Forest model (`POST /api/predict`) and optionally commit detected attacks directly onto the audit ledger.
- **Append-Only Containment**: Incident status transitions (`Open` ↔ `Contained`) never mutate historical records. Instead, `POST /api/incidents/{id}/status` appends a signed `status_change` block `{ type: "status_change", incident_id, new_status, by }`, and current status is derived from the latest block.
- **Workspace Controls**: Global incident search (`Ctrl/Cmd + K`), Critical/High alert bell with unread tracking, guided 4-step tour dialog, dark/light theme switcher, collapsible desktop/mobile sidebar, and configurable auto-refresh interval (`5s`, `15s`, `30s`, or `Off`).

## Tech Stack

- **Web App**: React 19, TypeScript, TanStack Start / Router / Query, Tailwind CSS v4, Radix UI, Recharts, Vite
- **Persistence**: Supabase Postgres (via Drizzle schema) with automatic local file-backed ledger fallback (`.data/sentinel-ledger.json`) when database credentials are unset
- **ML & Blockchain Utilities (`source/model/`)**: Python (scikit-learn, FastAPI, pytest) training pipeline, exported JSON Random Forest (`src/lib/threat/model/web-model.json`), and parity-checked SHA-256 canonical hashing

## Getting Started

### Prerequisites

- Node.js 20+
- `pnpm`

### Install & Run

```bash
pnpm install
pnpm dev
```

The development server runs at `http://localhost:3000`.

### Environment Variables

Copy `.env.example` to `.env` and populate your Supabase Postgres credentials if connecting to a hosted database. Without database credentials, Sentinel automatically initializes and persists a local SHA-256 ledger backed by the exported Random Forest model.

```bash
cp .env.example .env
```

### Scripts

| Command | Description |
| --- | --- |
| `pnpm dev` | Start Vite + TanStack Start dev server on port 3000 |
| `pnpm typecheck` | Run strict TypeScript typechecking (`tsc --noEmit`) |
| `pnpm build` | Build client and server production bundles |
| `pnpm test` | Run Vitest unit and component test suites |
| `pnpm lint` | Run ESLint across the repository |

## HTTP API Endpoints

- `GET /api/model/health` — Model metadata, 3-model evaluation metrics, confusion matrix, top-10 feature importances, live ledger stats, and drift status.
- `POST /api/incidents/{id}/status` — Append a `status_change` block (`{ "status": "Contained" | "Open", "by": "..." }`) to the hash chain.
- `POST /api/predict` — Score a network flow feature vector with the deployed Random Forest and optionally append detected attacks to the ledger.
- `GET /api/readme` — Serves this project documentation file for the in-app Help dialog.

## Python Model Pipeline (`source/model/`)

```bash
cd source/model
pip install -r requirements.txt
python train_model.py
pytest
```

## License

MIT
