# Repository Guidelines

- The security dashboard UI lives in `src/components/threat-dashboard`, while the Python model training and blockchain utilities live in `source/model`.
- Threat ledger mutations are strictly append-only: status changes append a `status_change` block rather than modifying existing rows.
- Keep secrets out of the repository and browser code; document required environment variables in `.env.example`.
