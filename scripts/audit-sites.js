// ═══════════════════════════════════════════════════════════════════════════════
// audit-sites.js — one-shot diagnostic for the site-column mismatch
// Run with:  netlify dev:exec node audit-sites.js
//   (or)    netlify env:import .env.local && node audit-sites.js
// This script only READS — it makes no changes to your data.
// ═══════════════════════════════════════════════════════════════════════════════
const { Pool } = require("pg");

const connStr = (process.env.DATABASE_URL || "")
  .replace("channel_binding=require", "channel_binding=prefer");

if (!connStr) {
  console.error("\n❌ DATABASE_URL not found in environment.");
  console.error("   Run with:  netlify dev:exec node audit-sites.js");
  console.error("   (or pull env first: netlify env:import .env.local)\n");
  process.exit(1);
}

const pool = new Pool({ connectionString: connStr, ssl: { rejectUnauthorized: false } });

const BAR = "═".repeat(72);
const DIM = "─".repeat(72);

async function main() {
  const c = await pool.connect();

  console.log("\n" + BAR);
  console.log("  HSSE Data Audit — site column distribution");
  console.log(BAR);

  // ── 1. Site value distribution per table ─────────────────────────────────
  const tables = ["observations", "ncr", "incidents", "equipment", "manpower", "risks"];
  for (const t of tables) {
    try {
      const { rows } = await c.query(`
        SELECT COALESCE(NULLIF(site, ''), '<blank/null>') AS site_value,
               COUNT(*)::int AS row_count
        FROM ${t}
        GROUP BY site_value
        ORDER BY row_count DESC
      `);
      const total = rows.reduce((a, r) => a + r.row_count, 0);
      console.log(`\n▸ ${t.toUpperCase()}  (total ${total} rows)`);
      console.log(DIM);
      if (rows.length === 0) {
        console.log("  (empty)");
      } else {
        rows.forEach(r => {
          const bar = "█".repeat(Math.min(30, Math.round(r.row_count / Math.max(1, total) * 30)));
          console.log(`  ${String(r.site_value).padEnd(28)} ${String(r.row_count).padStart(6)}   ${bar}`);
        });
      }
    } catch (e) {
      console.log(`\n▸ ${t.toUpperCase()} — ERROR: ${e.message}`);
    }
  }

  // ── 2. Users — role and site ──────────────────────────────────────────────
  console.log("\n" + BAR);
  console.log("  Users — role × site");
  console.log(BAR);
  try {
    const { rows } = await c.query(`
      SELECT id, email, name, role,
             COALESCE(NULLIF(site, ''), '<blank/null>') AS site,
             must_change_password AS must_change
      FROM users
      ORDER BY role, email
    `);
    if (rows.length === 0) {
      console.log("  (no users)");
    } else {
      console.log(`  ${"email".padEnd(36)} ${"role".padEnd(10)} ${"site".padEnd(16)} mustChange`);
      console.log(DIM);
      rows.forEach(u => {
        console.log(`  ${String(u.email || "").padEnd(36)} ${String(u.role || "").padEnd(10)} ${String(u.site).padEnd(16)} ${u.must_change ? "yes" : "no"}`);
      });
    }
  } catch (e) {
    console.log("  ERROR: " + e.message);
  }

  // ── 3. Settings — per-site manual stats presence ──────────────────────────
  console.log("\n" + BAR);
  console.log("  Settings keys (per-site manual stats)");
  console.log(BAR);
  try {
    const { rows } = await c.query(`
      SELECT key,
             CASE WHEN value IS NULL THEN 0 ELSE 1 END AS has_value,
             LENGTH(value::text)::int AS size_bytes
      FROM settings
      WHERE key IN ('site01Data', 'site02Data', 'site03Data', 'dashboardData')
         OR key LIKE 'site%Data'
      ORDER BY key
    `);
    if (rows.length === 0) {
      console.log("  No per-site settings keys exist yet.");
      console.log("  → Manual stats (Days Without LTI, Man-hours, etc.) will all show 0");
      console.log("    until an admin clicks 'Edit Stats → Save' on each site dashboard.");
    } else {
      rows.forEach(r => {
        console.log(`  ${r.key.padEnd(20)} ${r.has_value ? "✓" : "✗"}   ${r.size_bytes} bytes`);
      });
    }
  } catch (e) {
    console.log("  ERROR: " + e.message);
  }

  // ── 4. Sanity check — sample 3 rows from observations with site ──────────
  console.log("\n" + BAR);
  console.log("  Sample observations (first 5)");
  console.log(BAR);
  try {
    const { rows } = await c.query(`
      SELECT id, date, site, type, severity, status, observer
      FROM observations
      ORDER BY created_at DESC NULLS LAST
      LIMIT 5
    `);
    if (rows.length === 0) {
      console.log("  (no observations yet)");
    } else {
      rows.forEach(r => {
        console.log(`  ${String(r.id).slice(0, 24).padEnd(24)}  site='${r.site || ""}'  date=${r.date || "-"}  type=${r.type || "-"}  sev=${r.severity || "-"}`);
      });
    }
  } catch (e) {
    console.log("  ERROR: " + e.message);
  }

  console.log("\n" + BAR);
  console.log("  DONE — copy the output above and paste it back to Claude.");
  console.log(BAR + "\n");

  c.release();
  await pool.end();
}

main().catch(e => {
  console.error("\n❌ Audit failed:", e.message);
  process.exit(1);
});
