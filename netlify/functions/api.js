// ═══════════════════════════════════════════════════════════════════════════════
// HSSE Management System — Netlify Serverless API  v3.0
// Security-hardened, stable, production-ready
// ═══════════════════════════════════════════════════════════════════════════════

// ── Neon connection pool ──────────────────────────────────────────────────────
const { Pool }   = require("pg");
const crypto     = require("crypto");
const bcrypt     = require("bcryptjs");

const BCRYPT_ROUNDS = 10;

// Legacy hashes are 64-char hex (SHA256). Bcrypt hashes begin with $2.
const isLegacyHash = h => typeof h === "string" && /^[a-f0-9]{64}$/i.test(h);
const legacySha256 = p => crypto.createHash("sha256").update(p).digest("hex");

async function hashPassword(plain) {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

async function verifyPassword(plain, stored) {
  if (!stored) return false;
  if (isLegacyHash(stored)) return legacySha256(plain) === stored;
  try { return await bcrypt.compare(plain, stored); }
  catch { return false; }
}

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

// ── Response helpers ──────────────────────────────────────────────────────────
const cors = () => ({
  "Content-Type":                "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":"Content-Type, Authorization",
  "Access-Control-Allow-Methods":"GET, POST, PUT, PATCH, DELETE, OPTIONS",
});
const ok  = (data, status = 200) => ({ statusCode: status, headers: cors(), body: JSON.stringify(data) });
const err = (msg,  status = 500) => ({ statusCode: status, headers: cors(), body: JSON.stringify({ error: msg }) });

// ── JWT ───────────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  // Fail-fast: refuse to sign/verify tokens with a missing or weak secret.
  // Set JWT_SECRET in Netlify → Site → Environment variables to any 32+ char random string.
  console.error("[HSSE] FATAL: JWT_SECRET env var is missing or shorter than 32 chars");
}

function signToken(payload) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error("JWT_SECRET not configured");
  const header = Buffer.from(JSON.stringify({ alg:"HS256", typ:"JWT" })).toString("base64url");
  const body   = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString("base64url");
  const sig    = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  try {
    if (!token) return null;
    if (!JWT_SECRET || JWT_SECRET.length < 32) return null;
    const [header, body, sig] = token.split(".");
    if (!header || !body || !sig) return null;
    const expected = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url");
    // Constant-time comparison to avoid timing side-channels on signature check.
    const a = Buffer.from(sig); const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, "base64url").toString());
    // 8-hour expiry
    if (Date.now() - payload.iat > 8 * 60 * 60 * 1000) return null;
    return payload;
  } catch { return null; }
}

function getUser(event) {
  const auth  = (event.headers?.authorization || event.headers?.Authorization || "").trim();
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;
  return verifyToken(token);
}

// ── Input sanitisation ────────────────────────────────────────────────────────
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

// ── Collection → table whitelist (prevents SQL injection via collection name) ─
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
};

// ── Allowed columns per table (prevents SQL injection via field names in PUT) ─
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

// camelCase → snake_case
const toSnake = s => s.replace(/([A-Z])/g, "_$1").toLowerCase();

// ── Route parser ──────────────────────────────────────────────────────────────
function parseRoute(event) {
  const raw   = event.path.replace("/.netlify/functions/api","").replace(/^\/+/,"");
  const parts = raw.split("/").filter(Boolean);
  return { collection: parts[0] || "", id: parts[1] || null, method: event.httpMethod.toUpperCase() };
}

// ════════════════════════════════════════════════════════════════════════════
// AUTH HANDLERS
// ════════════════════════════════════════════════════════════════════════════

// In-memory rate limiter. Per-warm-instance only (Netlify functions recycle
// roughly every ~10 min idle) — acceptable first-line defence; upgrade to a
// shared store (Upstash/Redis) if multi-region traffic bypasses it.
const LOGIN_ATTEMPTS = new Map(); // key → { count, firstAttempt, lockedUntil }
const LOGIN_WINDOW_MS = 15 * 60 * 1000;  // 15 min rolling window
const LOGIN_MAX_TRIES = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000; // 15 min lockout after max tries

function rateLimitKey(event, email) {
  const ip = event.headers?.["x-nf-client-connection-ip"]
          || event.headers?.["x-forwarded-for"]?.split(",")[0]?.trim()
          || "unknown";
  return `${ip}|${(email || "").toLowerCase().trim()}`;
}

function checkLoginRate(key) {
  const now = Date.now();
  const rec = LOGIN_ATTEMPTS.get(key);
  if (!rec) return { allowed: true };
  if (rec.lockedUntil && rec.lockedUntil > now) {
    return { allowed: false, retryAfter: Math.ceil((rec.lockedUntil - now) / 1000) };
  }
  if (now - rec.firstAttempt > LOGIN_WINDOW_MS) {
    LOGIN_ATTEMPTS.delete(key);
    return { allowed: true };
  }
  return { allowed: true };
}

function recordLoginFailure(key) {
  const now = Date.now();
  const rec = LOGIN_ATTEMPTS.get(key) || { count: 0, firstAttempt: now };
  if (now - rec.firstAttempt > LOGIN_WINDOW_MS) {
    rec.count = 0; rec.firstAttempt = now; rec.lockedUntil = 0;
  }
  rec.count += 1;
  if (rec.count >= LOGIN_MAX_TRIES) rec.lockedUntil = now + LOGIN_LOCKOUT_MS;
  LOGIN_ATTEMPTS.set(key, rec);

  // Opportunistic GC so the Map doesn't grow unbounded on a long-warm instance.
  if (LOGIN_ATTEMPTS.size > 1000) {
    for (const [k, v] of LOGIN_ATTEMPTS) {
      if (now - v.firstAttempt > LOGIN_WINDOW_MS && (!v.lockedUntil || v.lockedUntil < now)) {
        LOGIN_ATTEMPTS.delete(k);
      }
    }
  }
}

function clearLoginRate(key) { LOGIN_ATTEMPTS.delete(key); }

async function handleLogin(event) {
  try {
    const body = JSON.parse(event.body || "{}");
    const { email, password } = body;
    if (!email || !password) return err("Email and password required", 400);
    if (typeof email !== "string" || typeof password !== "string") return err("Invalid input", 400);

    const rlKey = rateLimitKey(event, email);
    const rl = checkLoginRate(rlKey);
    if (!rl.allowed) {
      return {
        statusCode: 429,
        headers: { ...cors(), "Retry-After": String(rl.retryAfter) },
        body: JSON.stringify({ error: "Too many failed attempts. Try again later.", retryAfter: rl.retryAfter }),
      };
    }

    const pool = getPool();
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE LOWER(email)=LOWER($1)",
      [email.trim().slice(0,254)]
    );
    const user = rows[0];
    const matched = user ? await verifyPassword(password, user.password_hash) : false;

    if (!user || !matched) {
      recordLoginFailure(rlKey);
      console.error("[HSSE] Login failed for:", email.slice(0,50));
      return err("Invalid email or password", 401);
    }

    // Auto-upgrade legacy SHA256 hashes to bcrypt on successful login.
    if (isLegacyHash(user.password_hash)) {
      try {
        const upgraded = await hashPassword(password);
        await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [upgraded, user.id]);
      } catch (e) {
        console.error("[HSSE] Hash upgrade failed for user", user.id, e.message);
      }
    }

    clearLoginRate(rlKey);
    const token = signToken({ id:user.id, email:user.email, role:user.role, site:user.site });
    return ok({ token, user: {
      id:   user.id,    email:    user.email,  name:  user.name,
      role: user.role,  site:     user.site,   avatar:user.avatar,
      mustChangePassword: user.must_change_password,
      permissions: user.permissions || [],
    }});
  } catch(e) {
    console.error("[HSSE] handleLogin error:", e.message);
    return err("Login failed", 500);
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
    if (!password || typeof password !== "string" || password.length < 8)
      return err("Password must be at least 8 characters", 400);
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

// ════════════════════════════════════════════════════════════════════════════
// COLLECTION HANDLERS
// ════════════════════════════════════════════════════════════════════════════

async function handleGet(collection, id, event, user) {
  const TABLE = COLLECTION_TABLE[collection];
  if (!TABLE) return err(`Unknown collection: ${collection}`, 404);

  try {
    const pool = getPool();

    // Settings — flat key-value object
    if (TABLE === "settings") {
      if (id) {
        // GET /settings/site01Data — return specific key value
        const { rows } = await pool.query("SELECT value FROM settings WHERE key=$1", [id]);
        if (!rows.length) return ok(null); // key doesn't exist yet — not an error
        return ok(rows[0].value);          // return the value object directly
      }
      // GET /settings — return all keys as flat object
      const { rows } = await pool.query("SELECT key, value FROM settings ORDER BY key");
      const obj = {};
      rows.forEach(r => { obj[r.key] = r.value; });
      return ok(obj);
    }

    // Single document fetch
    if (id) {
      const { rows } = await pool.query(`SELECT * FROM ${TABLE} WHERE id=$1`, [id]);
      return rows.length ? ok(rows[0]) : err("Not found", 404);
    }

    // Collection fetch — site filtering via query param or user.site
    const qp       = event.queryStringParameters || {};
    const siteFilt  = qp.site ||
      (user.role !== "admin" && user.site !== "All Sites" ? user.site : null);

    let sqlQuery, params;
    if (siteFilt && !["risks","settings","users","weekly_reports"].includes(TABLE)) {
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
    return err("Fetch failed: " + e.message, 500);
  }
}

async function handlePost(collection, event, user) {
  if (!["admin","editor"].includes(user.role)) return err("No permission — editor or admin required", 403);
  const TABLE = COLLECTION_TABLE[collection];
  if (!TABLE) return err(`Cannot POST to ${collection}`, 400);

  try {
    const data = sanitiseObj(JSON.parse(event.body || "{}"));
    const pool = getPool();

    // Settings — key-value upsert
    // Supports two formats:
    // 1. {site01Data: {stats:{...}}}  → key="site01Data", value={stats:{...}}
    // 2. {zones:[...], obsTypes:[...]} → multiple top-level keys
    if (TABLE === "settings") {
      for (const [k, v] of Object.entries(data)) {
        if (k === "id") continue; // skip id field
        await pool.query(
          "INSERT INTO settings (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2::jsonb, updated_at=NOW()",
          [k, JSON.stringify(v)]
        );
      }
      return ok({ ok: true });
    }

    const id = data.id || data.uid || `${collection}-${Date.now()}`;

    // Privilege-escalation guard: only admins may set role/permissions/site on users.
    if (TABLE === "users" && user.role !== "admin") {
      delete data.role;
      delete data.permissions;
      delete data.site;
    }

    const handlers = {
      observations:  insObservation,
      ncr:           insNcr,
      risks:         insRisk,
      equipment:     insEquipment,
      manpower:      insManpower,
      incidents:     insIncident,
      users:         insUser,
      "weekly_reports": insWeeklyReport,
    };
    const fn = handlers[TABLE] || handlers[collection];
    if (!fn) return err(`No insert handler for ${collection}`, 400);
    const resultId = await fn(pool, { ...data, id });
    return ok({ ok: true, id: resultId || id });
  } catch(e) {
    console.error(`[HSSE] POST ${collection} error:`, e.message);
    return err("Insert failed: " + e.message, 500);
  }
}

async function handlePut(collection, id, event, user) {
  if (!["admin","editor"].includes(user.role)) return err("No permission", 403);
  if (!id) return err("ID required for update", 400);

  const TABLE = COLLECTION_TABLE[collection];
  if (!TABLE) return err("Unknown collection", 404);

  // Settings: merge new value into existing key
  if (TABLE === "settings") {
    try {
      const data = JSON.parse(event.body || "{}");
      const pool = getPool();
      // Get existing value and merge
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
      return err("Settings update failed: " + e.message, 500);
    }
  }

  try {
    const data    = sanitiseObj(JSON.parse(event.body || "{}"));
    const pool    = getPool();
    const allowed = ALLOWED_COLUMNS[TABLE] || [];

    // Privilege-escalation guard: only admins may alter role/permissions/site on users.
    // Non-admin edits on their own profile can still update name/avatar/etc.
    if (TABLE === "users" && user.role !== "admin") {
      delete data.role;
      delete data.permissions;
      delete data.site;
    }

    // Only update whitelisted columns — prevents SQL injection via field names
    const updates = Object.keys(data)
      .map(k => toSnake(k))
      .filter(k => allowed.includes(k) && k !== "id");

    if (!updates.length) {
      // Fallback: merge into raw column only
      await pool.query(`UPDATE ${TABLE} SET raw=COALESCE(raw,'{}'::jsonb)||$1::jsonb WHERE id=$2`,
        [JSON.stringify(data), id]);
      return ok({ ok: true });
    }

    const sets   = updates.map((col, i) => `${col}=$${i + 1}`);
    const vals   = updates.map(col => {
      // Map snake_case back to camelCase for lookup in data
      const camel = col.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
      const v     = data[col] !== undefined ? data[col] : data[camel];
      return typeof v === "object" && v !== null ? JSON.stringify(v) : v;
    });
    vals.push(id);
    await pool.query(`UPDATE ${TABLE} SET ${sets.join(",")} WHERE id=$${vals.length}`, vals);
    return ok({ ok: true });
  } catch(e) {
    console.error(`[HSSE] PUT ${collection}/${id} error:`, e.message);
    return err("Update failed: " + e.message, 500);
  }
}

async function handleDelete(collection, id, user) {
  if (user.role !== "admin") return err("No permission — admin only", 403);
  if (!id) return err("ID required for delete", 400);

  const TABLE = COLLECTION_TABLE[collection];
  if (!TABLE) return err("Unknown collection", 404);

  try {
    await getPool().query(`DELETE FROM ${TABLE} WHERE id=$1`, [id]);
    return ok({ ok: true });
  } catch(e) {
    console.error(`[HSSE] DELETE ${collection}/${id} error:`, e.message);
    return err("Delete failed: " + e.message, 500);
  }
}

// ════════════════════════════════════════════════════════════════════════════
// INSERT HELPERS — parameterized, null-safe, camelCase-aware
// ════════════════════════════════════════════════════════════════════════════

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
  const id   = d.id || d.uid || `user-${Date.now()}`;
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

// ════════════════════════════════════════════════════════════════════════════
// MAIN HANDLER
// ════════════════════════════════════════════════════════════════════════════
exports.handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors(), body: "" };
  }

  try {
    const path = event.path
      .replace("/.netlify/functions/api", "")
      .replace(/^\/+/, "");

    // ── Health check (no token required) ─────────────────────────────────────
    if (path === "health" || path === "health/") {
      let dbOk = false;
      try { await getPool().query("SELECT 1"); dbOk = true; } catch { /* dbOk stays false */ }
      return ok({
        status: dbOk ? "ok" : "degraded",
        db: dbOk,
        jwt: !!(JWT_SECRET && JWT_SECRET.length >= 32),
        time: new Date().toISOString(),
      }, dbOk ? 200 : 503);
    }

    // ── Auth routes (no token required) ──────────────────────────────────────
    if (path === "auth/login"           || path === "auth/login/")  return await handleLogin(event);
    if (path === "auth/me"              || path === "auth/me/")     return await handleMe(event);
    if (path === "auth/change-password" || path === "auth/change-password/")
      return await handleChangePassword(event);

    // ── All other routes require valid JWT ────────────────────────────────────
    const user = getUser(event);
    if (!user) return err("Unauthorised — please log in again", 401);

    const { collection, id, method } = parseRoute(event);

    if (method === "GET")                    return await handleGet(collection, id, event, user);
    if (method === "POST")                   return await handlePost(collection, event, user);
    if (method === "PUT" || method === "PATCH") return await handlePut(collection, id, event, user);
    if (method === "DELETE")                 return await handleDelete(collection, id, user);

    return err(`Method ${method} not supported`, 405);

  } catch(e) {
    console.error("[HSSE API] Unhandled error:", e.message, e.stack?.slice(0,300));
    return err("Internal server error", 500);
  }
};

// ── Test exports — unit tests require these helpers directly. Not part of the
// public runtime surface; deliberately not documented for consumers.
exports._test = {
  hashPassword, verifyPassword, isLegacyHash, legacySha256,
  signToken, verifyToken,
  rateLimitKey, checkLoginRate, recordLoginFailure, clearLoginRate,
  LOGIN_ATTEMPTS,
};
