#!/usr/bin/env node
// Runs a .sql file against DATABASE_URL, one statement at a time so that
// CREATE INDEX CONCURRENTLY (disallowed in a transaction) can run.
// Usage: DATABASE_URL=... node scripts/run-sql.js scripts/001_add_indexes.sql
const { Pool } = require("pg");
const fs       = require("fs");
const path     = require("path");

(async () => {
  const file = process.argv[2];
  if (!file) { console.error("Usage: node scripts/run-sql.js <file.sql>"); process.exit(1); }
  if (!process.env.DATABASE_URL) { console.error("DATABASE_URL is not set"); process.exit(1); }

  const raw = fs.readFileSync(path.resolve(file), "utf8");

  // Strip "-- ..." line comments, keep blank-line separation, then split on ; at EOL.
  const sql = raw.split("\n").filter(l => !l.trim().startsWith("--")).join("\n");
  const statements = sql.split(/;\s*(?:\n|$)/).map(s => s.trim()).filter(Boolean);

  const connStr = (process.env.DATABASE_URL || "").replace("channel_binding=require", "channel_binding=prefer");
  const pool = new Pool({ connectionString: connStr, ssl: { rejectUnauthorized: false } });

  let ok = 0, skipped = 0, failed = 0;
  for (const stmt of statements) {
    const preview = stmt.replace(/\s+/g, " ").slice(0, 80);
    try {
      await pool.query(stmt);
      console.log(`  ok    │ ${preview}`);
      ok++;
    } catch (e) {
      // 42P07 = relation already exists; harmless with IF NOT EXISTS but safety net
      if (e.code === "42P07") {
        console.log(`  skip  │ ${preview}  (already exists)`);
        skipped++;
      } else {
        console.error(`  FAIL  │ ${preview}\n         └─ ${e.code || ""} ${e.message}`);
        failed++;
      }
    }
  }
  await pool.end();
  console.log(`\nRan ${statements.length} statements — ok:${ok} skipped:${skipped} failed:${failed}`);
  process.exit(failed ? 1 : 0);
})();
