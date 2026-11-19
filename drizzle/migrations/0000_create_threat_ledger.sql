CREATE TABLE public.chain_blocks (
  block_index integer PRIMARY KEY CHECK (block_index >= 1),
  "timestamp" text NOT NULL,
  event jsonb NOT NULL,
  previous_hash text NOT NULL UNIQUE,
  hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON public.chain_blocks FROM anon, authenticated, service_role;
GRANT SELECT ON public.chain_blocks TO anon, authenticated;
GRANT SELECT, INSERT ON public.chain_blocks TO service_role;
ALTER TABLE public.chain_blocks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Ledger blocks are publicly readable" ON public.chain_blocks FOR SELECT TO anon, authenticated USING (true);

CREATE TABLE public.predictions (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  is_attack boolean NOT NULL,
  probability double precision NOT NULL CHECK (probability >= 0 AND probability <= 1),
  severity text NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX predictions_created_at_idx ON public.predictions (created_at DESC);
REVOKE ALL ON public.predictions FROM anon, authenticated, service_role;
GRANT SELECT ON public.predictions TO anon, authenticated;
GRANT SELECT, INSERT ON public.predictions TO service_role;
ALTER TABLE public.predictions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Predictions are publicly readable" ON public.predictions FOR SELECT TO anon, authenticated USING (true);

CREATE TABLE public.simulation_requests (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  client_key text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX simulation_requests_client_idx ON public.simulation_requests (client_key, created_at DESC);
REVOKE ALL ON public.simulation_requests FROM anon, authenticated, service_role;
GRANT SELECT, INSERT, DELETE ON public.simulation_requests TO service_role;
ALTER TABLE public.simulation_requests ENABLE ROW LEVEL SECURITY;

-- Aggregates so the dashboard does not need to download every row.
CREATE OR REPLACE FUNCTION public.threat_summary()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
  SELECT jsonb_build_object(
    'events_analyzed', (SELECT count(*) FROM public.predictions),
    'threats_detected', (SELECT count(*) FROM public.chain_blocks WHERE event->>'type' = 'detection'),
    'avg_confidence', (SELECT round(avg((event->>'confidence')::numeric), 2) FROM public.chain_blocks WHERE event->>'type' = 'detection'),
    'severity_counts', COALESCE((SELECT jsonb_object_agg(sev, n) FROM (
        SELECT event->>'severity' AS sev, count(*) AS n FROM public.chain_blocks
        WHERE event->>'type' = 'detection' GROUP BY 1) s), '{}'::jsonb),
    'chain_length', (SELECT count(*) FROM public.chain_blocks)
  );
$$;
GRANT EXECUTE ON FUNCTION public.threat_summary() TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.traffic_series(_hours integer DEFAULT 24, _bucket_hours integer DEFAULT 2)
RETURNS TABLE(bucket_start timestamptz, events bigint, threats bigint)
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
  WITH bounds AS (
    SELECT date_trunc('hour', now() - make_interval(hours => _hours)) AS start_at
  ), buckets AS (
    SELECT generate_series(b.start_at, now(), make_interval(hours => _bucket_hours)) AS bucket_start FROM bounds b
  )
  SELECT bk.bucket_start,
         count(p.id) AS events,
         count(p.id) FILTER (WHERE p.is_attack) AS threats
  FROM buckets bk
  LEFT JOIN public.predictions p
    ON p.created_at >= bk.bucket_start AND p.created_at < bk.bucket_start + make_interval(hours => _bucket_hours)
  GROUP BY bk.bucket_start
  ORDER BY bk.bucket_start;
$$;
GRANT EXECUTE ON FUNCTION public.traffic_series(integer, integer) TO anon, authenticated, service_role;