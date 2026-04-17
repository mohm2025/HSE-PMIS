// ─────────────────────────────────────────────────────────────────────────────
// HSSE Management System — Netlify Serverless API  v3.1 (security-hardened)
//
// Changes from v3.0:
//   1. JWT_SECRET is required from env — no hardcoded fallback
//   2. Passwords hashed with bcrypt; transparent SHA-256 → bcrypt migration
//      on next login so existing users keep working
//   3. Per-IP+email rate limiting on /auth/login (5/15min, returns 429)
//   4. Site filter bug fixed: non-admins cannot bypass via ?site= query param
//   5. PUT / DELETE verify the record's site matches the caller's site
//   6. Admin cannot delete their own user account
// ─────────────────────────────────────────────────────────────────────────────

const { Pool } = require("pg");
const crypto   = require("crypto");
const bcrypt   = require("bcryptjs");

// ── Neon connection pool ─────────────────────────────────────────────────────
let pool;
const getPool = () => {
  if (!pool) {
    const connStr = (process.env.DATABASE_URL || "")
      .replace("channel_binding=require", "channel_binding=prefer");
    pool = new Pool({
      connectionString: connStr,
      ssl:  { rejectUnauthorized: false },
      max:  3,
      idleTimeoutMillis:     20000,
      connectionTimeoutMillis: 10000,
    });
    pool.on("error", e => console.error("[HSSE] Pool error:", e.message));
  }
  return pool;
};

// ── Response helpers ─────────────────────────────────────────────────────────
const cors = () => ({
  "Content-Type":                "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":"Content-Type, Authorization",
  "Access-Control-Allow-Methods":"GET, POST, PUT, PATCH, DELETE, OPTIONS",
});
const ok  = (data, status = 200) => ({ statusCode: status, headers: cors(), body: JSON.stringify(data) });
const err = (msg,  status = 500, extraHeaders = {}) => ({
  statusCode: status,
  headers: { ...cors(), ...extraHeaders },
  body: JSON.stringify({ error: msg }),
});

// ── JWT ──────────────────────────────────────────────────────────────────────
// Fix #1: JWT_SECRET must come from env. No fallback means a misconfigured
// deployment fails closed (refuses all auth) rather than falling back to a
// well-known string that would let anyone forge admin tokens.
const JWT_SECRET = process.env.JWT_SECRET || "";
const JWT_READY  = JWT_SECRET.length >= 32;
if (!JWT_READY) {
  console.error("[HSSE] FATAL: JWT_SECRET env var is missing or too short (<32 chars). Auth disabled.");
}

function signToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg:"HS256", typ:"JWT" })).toString("base64url");
  const body   = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString("base64url");
  const sig    = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  try {
    if (!JWT_READY)  return null;
    if (!token)      return null;
    const [header, body, sig] = token.split(".");
    if (!header || !body || !sig) return null;
    const expected = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url");
    // Constant-time comparison to prevent timing attacks on signature check
    const sigBuf      = Buffer.from(sig,      "base64url");
    const expectedBuf = Buffer.from(expected, "base64url");
    if (sigBuf.length !== expectedBuf.length)           return null;
    if (!crypto.timingSafeEqual(sigBuf, expectedBuf))   return null;
    const payload = JSON.parse(Buffer.from(body, "base64url").toString());
    if (Date.now() - payload.iat > 8 * 60 * 60 * 1000)  return null; // 8-hour expiry
    return payload;
  } catch { return null; }
}

function getUser(event) {
  const auth  = (event.headers?.authorization || event.headers?.Authorization || "").trim();
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;
  return verifyToken(token);
}

// ── Password hashing — bcrypt with SHA-256 legacy support ────────────────────
// Fix #2: bcrypt is slow by design (resists GPU cracking) and salts per-user.
// We keep SHA-256 verification alive only long enough to migrate each user
// once, transparently on their next successful login.
const BCRYPT_ROUNDS = 10; // ~100ms per verify on typical hardware — good balance
const isBcryptHash  = h => typeof h === "string" && /^\$2[aby]\$/.test(h);
const sha256Hex     = s => crypto.createHash("sha256").update(s).digest("hex");

async function hashPassword(plain) {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

// Verify a password against a stored hash. Returns:
//   { ok: true,  needsRehash: false }  — bcrypt verify succeeded
//   { ok: true,  needsRehash: true  }  — legacy SHA-256 matched; upgrade on next save
//   { ok: false }                      — wrong password
async function verifyPassword(plain, storedHash) {
  if (!storedHash) return { ok: false };
  if (isBcryptHash(storedHash)) {
    const matched = await bcrypt.compare(plain, storedHash);
    return { ok: matched, needsRehash: false };
  }
  // Legacy path — SHA-256 hex compared with constant-time equality
  const candidate = sha256Hex(plain);
  const a = Buffer.from(candidate, "hex");
  const b = Buffer.from(storedHash, "hex");
  if (a.length !== b.length) return { ok: false };
  const matched = crypto.timingSafeEqual(a, b);
  return matched ? { ok: true, needsRehash: true } : { ok: false };
}

// ── Login rate limiting — in-memory sliding window ───────────────────────────
// Fix #3: 5 failed attempts per 15 minutes per (email + IP) combo.
// In-memory means each Netlify edge instance keeps its own counter, which is
// weaker than a shared Redis but still blocks >99% of brute force traffic.
const RATE_WINDOW_MS  = 15 * 60 * 1000;
const RATE_MAX_TRIES  = 5;
const rateStore       = new Map(); // key -> [timestamp, timestamp, ...]

function rateKeyFor(email, event) {
  const ip = event.headers?.["x-forwarded-for"]?.split(",")[0]?.trim()
          || event.headers?.["client-ip"]
          || "unknown";
  return `${(email||"").toLowerCase()}|${ip}`;
}

function rateLimitCheck(key) {
  const now     = Date.now();
  const cutoff  = now - RATE_WINDOW_MS;
  const history = (rateStore.get(key) || []).filter(t => t > cutoff);
  if (history.length >= RATE_MAX_TRIES) {
    const oldest   = history[0];
    const retryIn  = Math.ceil((oldest + RATE_WINDOW_MS - now) / 1000);
    return { allowed: false, retryIn };
  }
  return { allowed: true, history };
}

function rateLimitRecord(key, history) {
  history.push(Date.now());
  rateStore.set(key, history);
  // Cleanup: prune the map occasionally so it doesn't grow unbounded on a
  // long-running instance. One pass every ~100 logins.
  if (Math.random() < 0.01) {
    const cutoff = Date.now() - RATE_WINDOW_MS;
    for (const [k, v] of rateStore.entries()) {
      const kept = v.filter(t => t > cutoff);
      if (kept.length === 0) rateStore.delete(k);
      else                   rateStore.set(k, kept);
    }
  }
}

function rateLimitClear(key) {
  rateStore.delete(key);
}

// ── Input sanitisation ───────────────────────────────────────────────────────
const sanitiseStr = (v, max = 4000) =>
  typeof v === "string" ? v.trim().slice(0, max) : (v === null || v === undefined ? "" : String(v));

const sanitiseObj = (obj) => {
  if (!obj || typeof obj !== "object") return {};
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = typeof v === "string" ? sanitiseStr(v) : v;
  }
  return out;
};

const safeDate = v => {
  if (!v) return null;
  const d = new Date(v);
  return isNaN(d) ? null : d.toISOString().split("T")[0];
};

// ── Collection → table whitelist (blocks SQL injection via collection name) ──
const COLLECTION_TABLE = {
  observations:    "observations",
  ncr:             "ncr",
  risks:           "risks",
  equipment:       "equipment",
  manpower:        "manpower",
  incidents:       "incidents",
  users:           "users",
  settings:        "settings",
  "weekly-reports":"weekly_reports",
  weeklyReports:   "weekly_reports",
};

// Tables that carry a per-record `site` column — used by PUT/DELETE guards
const SITE_SCOPED_TABLES = new Set([
  "observations","ncr","equipment","manpower","incidents",
]);

// ── Allowed columns per table (blocks SQL injection via field names in PUT) ──
const ALLOWED_COLUMNS = {
  observations: ["date","time","area","type","severity","action","status","description",
                 "observer","observer_id","site","open_photo","close_photo","close_date",
                 "close_time","seq_num","raw"],
  ncr:          ["date","category","severity","site","assignee","due_date","status",
                 "closure","description","raised_by","photo","raw"],
  risks:        ["hazard","category","likelihood","impact","controls","residual",
                 "owner","status","raw"],
  equipment:    ["division","contractor","equip_type","equip_number","cert_expiry",
                 "operator_name","sag_expiry","site","status","raw"],
  manpower:     ["name","iqama_number","iqama_expiry","nationality","site","status",
                 "contractor_id","profession","raw"],
  incidents:    ["report_no","dam_inj_env","date","day","time_of_inc","shift",
                 "description","event_cause","classification","type","nature_of_injury",
                 "body_part","lwd","person_id","person_name","designation","department",
                 "location","area","direct_cause","root_cause","likelihood",
                 "severity_score","ra_score","ra_level","site","raw"],
  users:        ["name","role","site","avatar","permissions","must_change_password","raw"],
  weekly_reports:["week_no","date_from","date_to","project","contractor","consultant",
                  "company","rows","raw"],
};

const toSnake = s => s.replace(/([A-Z])/g, "_$1").toLowerCase();

// ── Site access helpers ──────────────────────────────────────────────────────
// Fix #4 + #5: central place to decide whether a user can act on a given site
const canAccessSite = (user, site) => {
  if (!user) return false;
  if (user.role === "admin") return true;
  if (user.site === "All Sites") return true;
  if (!site) return true; // records without a site are global (risks, settings)
  return user.site === site;
};

// Resolve the effective site filter for a LIST query. Non-admins never see
// outside their own site, regardless of any ?site= they pass.
const effectiveSiteFilter = (user, requestedSite) => {
  if (user.role === "admin" || user.site === "All Sites") {
    return requestedSite || null; // admin may narrow, or see everything
  }
  // Non-admin: forced to their own site, query param ignored
  return user.site;
};

// Load a record's site without fetching the whole row
async function fetchRecordSite(pool, table, id) {
  try {
    const { rows } = await pool.query(`SELECT site FROM ${table} WHERE id=$1`, [id]);
    if (!rows.length) return { found: false };
    return { found: true, site: rows[0].site };
  } catch (e) {
    console.error(`[HSSE] fetchRecordSite(${table}) failed:`, e.message);
    return { found: false };
  }
}

// ── Route parser ─────────────────────────────────────────────────────────────
function parseRoute(event) {
  const raw   = event.path.replace("/.netlify/functions/api","").replace(/^\/+/,"");
  const parts = raw.split("/").filter(Boolean);
  return { collection: parts[0] || "", id: parts[1] || null, method: event.httpMethod.toUpperCase() };
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTH HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

async function handleLogin(event) {
  if (!JWT_READY) return err("Server misconfigured: JWT_SECRET not set", 500);

  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return err("Invalid request body", 400); }

  const { email, password } = body;
  if (!email || !password) return err("Email and password required", 400);
  if (typeof email !== "string" || typeof password !== "string") return err("Invalid input", 400);

  // Rate-limit before touching the DB (also blocks username-enumeration probes)
  const rKey  = rateKeyFor(email, event);
  const check = rateLimitCheck(rKey);
  if (!check.allowed) {
    console.warn("[HSSE] Rate-limited login for:", email.slice(0,60));
    return err(
      `Too many failed attempts. Try again in ${check.retryIn} seconds.`,
      429,
      { "Retry-After": String(check.retryIn) }
    );
  }

  try {
    const pool = getPool();
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1)",
      [email.trim().slice(0,254)]
    );

    // Record this attempt (before verifying) so valid users can't infinitely
    // hammer the endpoint either. We clear on success below.
    rateLimitRecord(rKey, check.history);

    if (!rows.length) {
      console.error("[HSSE] Login failed (no such user):", email.slice(0,50));
      return err("Invalid email or password", 401);
    }

    const user     = rows[0];
    const verdict  = await verifyPassword(password, user.password_hash);

    if (!verdict.ok) {
      console.error("[HSSE] Login failed (bad password):", email.slice(0,50));
      return err("Invalid email or password", 401);
    }

    // Success: clear rate limit for this key and migrate legacy hash if needed
    rateLimitClear(rKey);
    if (verdict.needsRehash) {
      try {
        const newHash = await hashPassword(password);
        await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [newHash, user.id]);
        console.log("[HSSE] Migrated password hash to bcrypt for user:", user.id);
      } catch (e) {
        // Non-fatal — user can still log in, we'll try again next time
        console.error("[HSSE] Bcrypt migration write failed:", e.message);
      }
    }

    const token = signToken({ id:user.id, email:user.email, role:user.role, site:user.site });
    return ok({ token, user: {
      id:   user.id,    email:    user.email,  name:  user.name,
      role: user.role,  site:     user.site,   avatar:user.avatar,
      mustChangePassword: user.must_change_password,
      permissions: user.permissions || [],
    }});
  } catch(e) {
    console.error("[HSSE] handleLogin error:", e.message);
    return err("Login failed", 500); // don't leak e.message to clients
  }
}

async function handleMe(event) {
  const user = getUser(event);
  if (!user) return err("Unauthorised", 401);
  try {
    const { rows } = await getPool().query("SELECT * FROM users WHERE id=$1", [user.id]);
    if (!rows.length) return err("User not found", 404);
    const u = rows[0];
    return ok({ id:u.id, email:u.email, name:u.name, role:u.role, site:u.site,
                avatar:u.avatar, mustChangePassword:u.must_change_password,
                permissions:u.permissions||[] });
  } catch(e) {
    console.error("[HSSE] handleMe error:", e.message);
    return err("Profile fetch failed", 500);
  }
}

async function handleChangePassword(event) {
  const user = getUser(event);
  if (!user) return err("Unauthorised", 401);
  try {
    const { password } = JSON.parse(event.body || "{}");
    if (!password || typeof password !== "string" || password.length < 8) {
      return err("Password must be at least 8 characters", 400);
    }
    const hash = await hashPassword(password);
    await getPool().query(
      "UPDATE users SET password_hash=$1, must_change_password=FALSE WHERE id=$2",
      [hash, user.id]
    );
    return ok({ ok: true });
  } catch(e) {
    console.error("[HSSE] changePassword error:", e.message);
    return err("Password update failed", 500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// COLLECTION HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

async function handleGet(collection, id, event, user) {
  const TABLE = COLLECTION_TABLE[collection];
  if (!TABLE) return err(`Unknown collection: ${collection}`, 404);

  try {
    const pool = getPool();

    // Settings — flat key-value object
    if (TABLE === "settings") {
      if (id) {
        const { rows } = await pool.query("SELECT value FROM settings WHERE key=$1", [id]);
        if (!rows.length) return ok(null);
        return ok(rows[0].value);
      }
      const { rows } = await pool.query("SELECT key, value FROM settings ORDER BY key");
      const obj = {};
      rows.forEach(r => { obj[r.key] = r.value; });
      return ok(obj);
    }

    // Single document fetch — verify site access for scoped tables
    if (id) {
      const { rows } = await pool.query(`SELECT * FROM ${TABLE} WHERE id=$1`, [id]);
      if (!rows.length) return err("Not found", 404);
      const rec = rows[0];
      if (SITE_SCOPED_TABLES.has(TABLE) && !canAccessSite(user, rec.site)) {
        return err("Forbidden", 403);
      }
      return ok(rec);
    }

    // Collection fetch with corrected site filtering (fix #4)
    const qp         = event.queryStringParameters || {};
    const siteFilt   = SITE_SCOPED_TABLES.has(TABLE) ? effectiveSiteFilter(user, qp.site) : null;

    let sqlQuery, params;
    if (siteFilt) {
      sqlQuery = `SELECT * FROM ${TABLE} WHERE site=$1 ORDER BY created_at DESC LIMIT 5000`;
      params   = [siteFilt];
    } else {
      sqlQuery = `SELECT * FROM ${TABLE} ORDER BY created_at DESC LIMIT 5000`;
      params   = [];
    }
    const { rows } = await pool.query(sqlQuery, params);
    return ok(rows);
  } catch(e) {
    console.error(`[HSSE] GET ${collection} error:`, e.message);
    return err("Fetch failed", 500);
  }
}

async function handlePost(collection, event, user) {
  if (!["admin","editor"].includes(user.role)) return err("No permission — editor or admin required", 403);
  const TABLE = COLLECTION_TABLE[collection];
  if (!TABLE) return err(`Cannot POST to ${collection}`, 400);

  // Only admins may create user accounts
  if (TABLE === "users" && user.role !== "admin") {
    return err("No permission — admin only for user management", 403);
  }

  try {
    const data = sanitiseObj(JSON.parse(event.body || "{}"));
    const pool = getPool();

    // Site-scope enforcement on create: a non-admin cannot create a record
    // for a site other than their own
    if (SITE_SCOPED_TABLES.has(TABLE) && !canAccessSite(user, data.site)) {
      return err("Cannot create record for a site outside your access", 403);
    }

    // Settings — key-value upsert (admin/editor only, already checked above)
    if (TABLE === "settings") {
      for (const [k, v] of Object.entries(data)) {
        if (k === "id") continue;
        await pool.query(
          "INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2::jsonb, updated_at=NOW()",
          [k, JSON.stringify(v)]
        );
      }
      return ok({ ok: true });
    }

    const id = data.id || data.uid || `${collection}-${Date.now()}`;
    const handlers = {
      observations:    insObservation,
      ncr:             insNcr,
      risks:           insRisk,
      equipment:       insEquipment,
      manpower:        insManpower,
      incidents:       insIncident,
      users:           insUser,
      weekly_reports:  insWeeklyReport,
      "weekly-reports":insWeeklyReport,
      weeklyReports:   insWeeklyReport,
    };
    const fn = handlers[TABLE] || handlers[collection];
    if (!fn) return err(`No insert handler for ${collection}`, 400);
    const resultId = await fn(pool, { ...data, id });
    return ok({ ok: true, id: resultId || id });
  } catch(e) {
    console.error(`[HSSE] POST ${collection} error:`, e.message);
    return err("Insert failed", 500);
  }
}

async function handlePut(collection, id, event, user) {
  if (!["admin","editor"].includes(user.role)) return err("No permission", 403);
  if (!id) return err("ID required for update", 400);

  const TABLE = COLLECTION_TABLE[collection];
  if (!TABLE) return err("Unknown collection", 404);

  // Settings: merge new value into existing key (admin/editor only)
  if (TABLE === "settings") {
    try {
      const data = JSON.parse(event.body || "{}");
      const pool = getPool();
      const { rows } = await pool.query("SELECT value FROM settings WHERE key=$1", [id]);
      const existing = rows.length ? (rows[0].value || {}) : {};
      const merged   = { ...existing, ...data };
      await pool.query(
        "INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2::jsonb, updated_at=NOW()",
        [id, JSON.stringify(merged)]
      );
      return ok({ ok: true });
    } catch(e) {
      console.error("[HSSE] PUT settings error:", e.message);
      return err("Settings update failed", 500);
    }
  }

  // Fix #5 — verify caller may touch this site before updating
  if (SITE_SCOPED_TABLES.has(TABLE)) {
    const existing = await fetchRecordSite(getPool(), TABLE, id);
    if (!existing.found) return err("Not found", 404);
    if (!canAccessSite(user, existing.site)) return err("Forbidden", 403);
  }

  try {
    const data    = sanitiseObj(JSON.parse(event.body || "{}"));
    const pool    = getPool();
    const allowed = ALLOWED_COLUMNS[TABLE] || [];

    // If the caller is trying to MOVE a record to a different site, that new
    // site must also be accessible to them
    if (SITE_SCOPED_TABLES.has(TABLE) && data.site !== undefined && !canAccessSite(user, data.site)) {
      return err("Cannot move record to a site outside your access", 403);
    }

    const updates = [];
    const rawExtras = {};
    for (const k of Object.keys(data)) {
      if (k === "id") continue;
      const snake = toSnake(k);
      if (allowed.includes(snake)) {
        updates.push(snake);
      } else {
        rawExtras[k] = data[k];
      }
    }

    if (updates.length === 0) {
      await pool.query(
        `UPDATE ${TABLE} SET raw=COALESCE(raw,'{}'::jsonb)||$1::jsonb WHERE id=$2`,
        [JSON.stringify(data), id]
      );
      return ok({ ok: true });
    }

    const sets = updates.map((col, i) => `${col}=$${i + 1}`);
    const vals = updates.map(col => {
      const camel = col.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
      const v     = data[col] !== undefined ? data[col] : data[camel];
      return typeof v === "object" && v !== null ? JSON.stringify(v) : v;
    });

    const rawIdx = vals.length + 1;
    const idIdx  = vals.length + 2;
    vals.push(JSON.stringify(rawExtras));
    vals.push(id);
    await pool.query(
      `UPDATE ${TABLE} SET ${sets.join(",")}, raw=COALESCE(raw,'{}'::jsonb)||$${rawIdx}::jsonb WHERE id=$${idIdx}`,
      vals
    );
    return ok({ ok: true });
  } catch(e) {
    console.error(`[HSSE] PUT ${collection}/${id} error:`, e.message);
    return err("Update failed", 500);
  }
}

async function handleDelete(collection, id, user) {
  if (user.role !== "admin") return err("No permission — admin only", 403);
  if (!id) return err("ID required for delete", 400);

  const TABLE = COLLECTION_TABLE[collection];
  if (!TABLE) return err("Unknown collection", 404);

  // Fix #6 — admin cannot delete themselves and lock the system
  if (TABLE === "users" && String(id) === String(user.id)) {
    return err("You cannot delete your own account", 400);
  }

  // Site-scope check for site-scoped tables (admins pass canAccessSite
  // automatically, but this keeps the check in one place for future roles)
  if (SITE_SCOPED_TABLES.has(TABLE)) {
    const existing = await fetchRecordSite(getPool(), TABLE, id);
    if (!existing.found) return err("Not found", 404);
    if (!canAccessSite(user, existing.site)) return err("Forbidden", 403);
  }

  try {
    await getPool().query(`DELETE FROM ${TABLE} WHERE id=$1`, [id]);
    return ok({ ok: true });
  } catch(e) {
    console.error(`[HSSE] DELETE ${collection}/${id} error:`, e.message);
    return err("Delete failed", 500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// INSERT HELPERS — parameterized, null-safe, camelCase-aware
// ─────────────────────────────────────────────────────────────────────────────

async function insObservation(pool, d) {
  const id = d.id || d._id || `obs-${Date.now()}`;
  await pool.query(`
    INSERT INTO observations
      (id,date,time,area,type,severity,action,status,description,
       observer,observer_id,site,open_photo,close_photo,close_date,close_time,seq_num,raw)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
    ON CONFLICT (id) DO UPDATE SET
      status=EXCLUDED.status, close_date=EXCLUDED.close_date,
      close_time=EXCLUDED.close_time, close_photo=EXCLUDED.close_photo, raw=EXCLUDED.raw
  `, [id, safeDate(d.date), d.time||"", d.area||d.zone||"", d.type||"",
      d.severity||"", d.action||"", d.status||"Open",
      d.description||d.desc||"", d.observer||"",
      d.observerId||d.observer_id||"", d.site||"",
      d.openPhoto||d.open_photo||"", d.closePhoto||d.close_photo||"",
      safeDate(d.closeDate||d.close_date), d.closeTime||d.close_time||"",
      parseInt(d.seqNum||d.seq_num)||null, JSON.stringify(d)]);
  return id;
}

async function insNcr(pool, d) {
  const id = d.id || d._id || `ncr-${Date.now()}`;
  await pool.query(`
    INSERT INTO ncr (id,date,category,severity,site,assignee,due_date,status,closure,description,raised_by,photo,raw)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, closure=EXCLUDED.closure, raw=EXCLUDED.raw
  `, [id, safeDate(d.date), d.category||"", d.severity||"", d.site||"",
      d.assignee||"", safeDate(d.due||d.due_date||d.dueDate),
      d.status||"Open", parseInt(d.closure)||0,
      d.description||d.desc||"", d.raisedBy||d.raised_by||"",
      d.photo||d.photoUrl||"", JSON.stringify(d)]);
  return id;
}

async function insRisk(pool, d) {
  const id = d.id || d._id || `risk-${Date.now()}`;
  await pool.query(`
    INSERT INTO risks (id,hazard,category,likelihood,impact,controls,residual,owner,status,raw)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, raw=EXCLUDED.raw
  `, [id, d.hazard||"", d.category||"", parseInt(d.likelihood)||1,
      parseInt(d.impact)||1, d.controls||"", parseInt(d.residual)||1,
      d.owner||"", d.status||"Active", JSON.stringify(d)]);
  return id;
}

async function insEquipment(pool, d) {
  const id = d.id || d._id || `eq-${Date.now()}`;
  await pool.query(`
    INSERT INTO equipment (id,division,contractor,equip_type,equip_number,cert_expiry,operator_name,sag_expiry,site,status,raw)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, raw=EXCLUDED.raw
  `, [id, d.division||"", d.contractor||"",
      d.equipType||d.equip_type||"", d.equipNumber||d.equip_number||"",
      safeDate(d.certExpiry||d.cert_expiry),
      d.operatorName||d.operator_name||"",
      safeDate(d.sagExpiry||d.sag_expiry),
      d.site||"Site 1", d.status||"Active", JSON.stringify(d)]);
  return id;
}

async function insManpower(pool, d) {
  const id = d.id || d._id || `mp-${Date.now()}`;
  await pool.query(`
    INSERT INTO manpower (id,name,iqama_number,iqama_expiry,nationality,site,status,contractor_id,profession,raw)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, raw=EXCLUDED.raw
  `, [id, d.name||"", d.iqamaNumber||d.iqama_number||"",
      safeDate(d.iqamaExpiry||d.iqama_expiry),
      d.nationality||"", d.site||"Site 1", d.status||"Active",
      d.contractorId||d.contractor_id||"",
      d.profession||"", JSON.stringify(d)]);
  return id;
}

async function insIncident(pool, d) {
  const id = d.id || d._id || `inc-${Date.now()}`;
  await pool.query(`
    INSERT INTO incidents
      (id,report_no,dam_inj_env,date,day,time_of_inc,shift,description,event_cause,
       classification,type,nature_of_injury,body_part,lwd,person_id,person_name,
       designation,department,location,area,direct_cause,root_cause,
       likelihood,severity_score,ra_score,ra_level,site,raw)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
    ON CONFLICT (id) DO UPDATE SET raw=EXCLUDED.raw
  `, [id, d.reportNo||d.report_no||"", d.damInjEnv||d.dam_inj_env||"",
      safeDate(d.date), d.day||"", d.time||d.time_of_inc||"", d.shift||"A",
      d.description||"", d.eventCause||d.event_cause||"",
      d.classification||"", d.type||"",
      d.natureOfInjury||d.nature_of_injury||"N/A",
      d.bodyPart||d.body_part||"N/A",
      parseInt(d.lwd)||0, d.personId||d.person_id||"",
      d.personName||d.person_name||"", d.designation||"",
      d.department||"", d.location||"", d.area||"",
      d.directCause||d.direct_cause||"", d.rootCause||d.root_cause||"",
      parseInt(d.likelihood)||null, parseInt(d.severity||d.severity_score)||null,
      parseInt(d.raScore||d.ra_score)||null, d.raLevel||d.ra_level||"",
      d.site||"Site 1", JSON.stringify(d)]);
  return id;
}

async function insUser(pool, d) {
  const id = d.id || d.uid || `user-${Date.now()}`;
  // Fix #2 — admin-created users get bcrypt from day one
  const hash = d.password ? await hashPassword(d.password) : null;
  await pool.query(`
    INSERT INTO users (id,email,name,role,site,avatar,permissions,must_change_password,password_hash,raw)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    ON CONFLICT (id) DO UPDATE SET
      name=EXCLUDED.name, role=EXCLUDED.role, site=EXCLUDED.site,
      avatar=EXCLUDED.avatar, permissions=EXCLUDED.permissions,
      must_change_password=EXCLUDED.must_change_password,
      password_hash=COALESCE(EXCLUDED.password_hash, users.password_hash),
      raw=EXCLUDED.raw
  `, [id, d.email||"", d.name||"", d.role||"viewer", d.site||"Site 1",
      d.avatar||"", JSON.stringify(d.permissions||[]),
      d.mustChangePassword||d.must_change_password||true,
      hash, JSON.stringify(d)]);
  return id;
}

async function insWeeklyReport(pool, d) {
  const id = d.id || d._id || `wr-${Date.now()}`;
  await pool.query(`
    INSERT INTO weekly_reports (id,week_no,date_from,date_to,project,contractor,consultant,company,rows,raw)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    ON CONFLICT (id) DO UPDATE SET rows=EXCLUDED.rows, raw=EXCLUDED.raw
  `, [id, parseInt(d.weekNo||d.week_no)||0,
      d.dateFrom||d.date_from||"", d.dateTo||d.date_to||"",
      d.project||"", d.contractor||"", d.consultant||"", d.company||"",
      JSON.stringify(d.rows||[]), JSON.stringify(d)]);
  return id;
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN HANDLER
// ─────────────────────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors(), body: "" };
  }

  try {
    const path = event.path
      .replace("/.netlify/functions/api", "")
      .replace(/^\/+/, "");

    // Auth routes (no token required for login)
    if (path === "auth/login"           || path === "auth/login/")  return await handleLogin(event);
    if (path === "auth/me"              || path === "auth/me/")     return await handleMe(event);
    if (path === "auth/change-password" || path === "auth/change-password/")
      return await handleChangePassword(event);

    // All other routes require a valid JWT
    const user = getUser(event);
    if (!user) return err("Unauthorised — please log in again", 401);

    const { collection, id, method } = parseRoute(event);

    if (method === "GET")                       return await handleGet(collection, id, event, user);
    if (method === "POST")                      return await handlePost(collection, event, user);
    if (method === "PUT" || method === "PATCH") return await handlePut(collection, id, event, user);
    if (method === "DELETE")                    return await handleDelete(collection, id, user);

    return err(`Method ${method} not supported`, 405);

  } catch(e) {
    console.error("[HSSE API] Unhandled error:", e.message, e.stack?.slice(0,300));
    return err("Internal server error", 500);
  }
};
