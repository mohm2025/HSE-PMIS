// ═══════════════════════════════════════════════════════════════════════════════
// audit-settings.js — peek inside site01Data / dashboardData to see structure
// Run with:  netlify dev:exec node audit-settings.js
// READ ONLY.
// ═══════════════════════════════════════════════════════════════════════════════
const { Pool } = require("pg");

const connStr = (process.env.DATABASE_URL || "")
  .replace("channel_binding=require", "channel_binding=prefer");

if (!connStr) {
  console.error("DATABASE_URL not found. Run: netlify dev:exec node audit-settings.js");
  process.exit(1);
}

const pool = new Pool({ connectionString: connStr, ssl: { rejectUnauthorized: false } });

(async () => {
  const c = await pool.connect();
  try {
    for (const key of ["site01Data", "site02Data", "site03Data", "dashboardData"]) {
      const { rows } = await c.query("SELECT value FROM settings WHERE key=$1", [key]);
      if (!rows.length) { console.log(`\n▸ ${key} — does NOT exist`); continue; }
      const v = rows[0].value || {};
      const topKeys = Object.keys(v);
      console.log(`\n▸ ${key}`);
      console.log("  top-level keys:", topKeys.join(", ") || "(none)");

      if (v.stats) {
        console.log("  stats:", Object.entries(v.stats).map(([k,val]) => `${k}=${val}`).join(", "));
      } else {
        console.log("  stats: (absent — this is why Man-hours grid shows zeros)");
      }

      if (v.manualStats) {
        console.log("  manualStats:", Object.entries(v.manualStats).map(([k,val]) => `${k}=${val}`).join(", "));
      }

      if (v.welfare)  console.log("  welfare items:", Array.isArray(v.welfare) ? v.welfare.length : "unknown");
      if (v.weekly)   console.log("  weekly rows:",   Array.isArray(v.weekly)  ? v.weekly.length  : "unknown");
      if (v.monthlyState) console.log("  monthlyState keys:", Object.keys(v.monthlyState).join(", "));
      if (v.ltiResetDate) console.log("  ltiResetDate:", v.ltiResetDate);
    }
  } finally {
    c.release();
    await pool.end();
  }
})().catch(e => { console.error(e.message); process.exit(1); });
