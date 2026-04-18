-- ─────────────────────────────────────────────────────────────────────────────
-- HSSE Management System — performance indexes
-- Run once against Neon:
--   psql "$DATABASE_URL" -f scripts/001_add_indexes.sql
-- or paste into Neon Console → SQL Editor.
--
-- All indexes use IF NOT EXISTS so re-running is safe.
-- CONCURRENTLY lets index builds run without blocking writes — Neon supports it.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── users ────────────────────────────────────────────────────────────────────
-- Login query filters by LOWER(email); match it with a functional index.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_lower
  ON users (LOWER(email));

-- ── observations ─────────────────────────────────────────────────────────────
-- Hot path: WHERE site=$1 ORDER BY created_at DESC LIMIT 5000
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_observations_site_created
  ON observations (site, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_observations_status
  ON observations (status);

-- ── ncr ──────────────────────────────────────────────────────────────────────
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ncr_site_created
  ON ncr (site, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ncr_status
  ON ncr (status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ncr_due_date
  ON ncr (due_date)
  WHERE status <> 'Closed';

-- ── incidents ────────────────────────────────────────────────────────────────
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_incidents_site_date
  ON incidents (site, date DESC);

-- ── equipment ────────────────────────────────────────────────────────────────
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_equipment_site
  ON equipment (site);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_equipment_cert_expiry
  ON equipment (cert_expiry)
  WHERE cert_expiry IS NOT NULL;

-- ── manpower ─────────────────────────────────────────────────────────────────
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_manpower_site
  ON manpower (site);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_manpower_iqama_expiry
  ON manpower (iqama_expiry)
  WHERE iqama_expiry IS NOT NULL;

-- ── risks ────────────────────────────────────────────────────────────────────
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_risks_status
  ON risks (status);

-- ── settings ─────────────────────────────────────────────────────────────────
-- settings.key is already primary key (per INSERT ... ON CONFLICT (key)) — no index needed.

-- ── weekly_reports ───────────────────────────────────────────────────────────
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_weekly_reports_week
  ON weekly_reports (week_no DESC);

-- ── After running, verify with ───────────────────────────────────────────────
-- SELECT schemaname, tablename, indexname FROM pg_indexes
-- WHERE schemaname = 'public' ORDER BY tablename, indexname;
