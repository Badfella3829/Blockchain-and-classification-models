CREATE INDEX IF NOT EXISTS chain_blocks_event_type_idx ON public.chain_blocks ((event->>'type'));
CREATE INDEX IF NOT EXISTS chain_blocks_incident_idx ON public.chain_blocks ((event->>'incident_id'), block_index DESC) WHERE event->>'type' = 'status_change';
CREATE INDEX IF NOT EXISTS chain_blocks_event_id_idx ON public.chain_blocks ((event->>'event_id')) WHERE event->>'type' = 'detection';

CREATE OR REPLACE VIEW public.incident_view
WITH (security_invoker = on) AS
SELECT
  d.block_index,
  d."timestamp" AS detected_at,
  d.hash,
  d.previous_hash,
  d.event->>'event_id' AS event_id,
  d.event->>'source' AS source,
  d.event->>'category' AS category,
  d.event->>'severity' AS severity,
  CASE d.event->>'severity' WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END AS severity_rank,
  (d.event->>'confidence')::double precision AS confidence,
  d.event->>'model_version' AS model_version,
  COALESCE(s.new_status, d.event->>'status', 'Open') AS status,
  s.block_index AS status_block_index,
  s.changed_at AS status_changed_at,
  s.changed_by AS status_changed_by
FROM public.chain_blocks d
LEFT JOIN LATERAL (
  SELECT c.event->>'new_status' AS new_status, c.block_index, c."timestamp" AS changed_at, c.event->>'by' AS changed_by
  FROM public.chain_blocks c
  WHERE c.event->>'type' = 'status_change' AND c.event->>'incident_id' = d.event->>'event_id'
  ORDER BY c.block_index DESC
  LIMIT 1
) s ON true
WHERE d.event->>'type' = 'detection';

GRANT SELECT ON public.incident_view TO anon, authenticated, service_role;

CREATE OR REPLACE FUNCTION public.threat_summary()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
  SELECT jsonb_build_object(
    'events_analyzed', (SELECT count(*) FROM public.predictions),
    'threats_detected', (SELECT count(*) FROM public.incident_view),
    'critical_open', (SELECT count(*) FROM public.incident_view WHERE severity = 'Critical' AND status = 'Open'),
    'open_incidents', (SELECT count(*) FROM public.incident_view WHERE status = 'Open'),
    'avg_confidence', (SELECT round(avg(confidence)::numeric, 2) FROM public.incident_view),
    'severity_counts', COALESCE((SELECT jsonb_object_agg(severity, n) FROM (
        SELECT severity, count(*) AS n FROM public.incident_view GROUP BY 1) s), '{}'::jsonb),
    'chain_length', (SELECT count(*) FROM public.chain_blocks)
  );
$$;

CREATE OR REPLACE FUNCTION public.model_live_stats()
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
  WITH today AS (
    SELECT count(*) AS n, count(*) FILTER (WHERE is_attack) AS attacks, avg(probability) FILTER (WHERE is_attack) AS avg_attack_p
    FROM public.predictions WHERE created_at >= date_trunc('day', now())
  ), recent AS (
    SELECT count(*) AS n, count(*) FILTER (WHERE is_attack) AS attacks
    FROM public.predictions WHERE created_at >= now() - interval '1 hour'
  ), earlier AS (
    SELECT count(*) AS n, count(*) FILTER (WHERE is_attack) AS attacks
    FROM public.predictions WHERE created_at >= now() - interval '25 hours' AND created_at < now() - interval '1 hour'
  )
  SELECT jsonb_build_object(
    'predictions_today', today.n,
    'attacks_today', today.attacks,
    'avg_attack_confidence', CASE WHEN today.avg_attack_p IS NULL THEN NULL ELSE round((today.avg_attack_p * 100)::numeric, 2) END,
    'recent_count', recent.n,
    'recent_attacks', recent.attacks,
    'earlier_count', earlier.n,
    'earlier_attacks', earlier.attacks
  )
  FROM today, recent, earlier;
$$;
GRANT EXECUTE ON FUNCTION public.model_live_stats() TO anon, authenticated, service_role;