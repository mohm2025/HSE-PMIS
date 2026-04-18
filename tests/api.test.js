// ─────────────────────────────────────────────────────────────────────────────
// netlify/functions/api.js — security-path tests
// Run:  npm run test:api
// Uses Node's built-in test runner (node --test) — no extra deps.
// ─────────────────────────────────────────────────────────────────────────────

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

// api.js requires JWT_SECRET on load. Stub before require().
process.env.JWT_SECRET  = process.env.JWT_SECRET  || crypto.randomBytes(48).toString("hex");
process.env.DATABASE_URL = process.env.DATABASE_URL || "postgresql://test:test@localhost/test_stub";

const { _test: api } = require("../netlify/functions/api.js");

// ── Password hashing ─────────────────────────────────────────────────────────
test("hashPassword produces a bcrypt hash starting with $2", async () => {
  const h = await api.hashPassword("correcthorsebatterystaple");
  assert.match(h, /^\$2[aby]\$/);
  assert.notEqual(h, "correcthorsebatterystaple");
});

test("hashPassword produces different hashes for the same input (salted)", async () => {
  const a = await api.hashPassword("same-password");
  const b = await api.hashPassword("same-password");
  assert.notEqual(a, b);
});

test("verifyPassword returns true for correct password", async () => {
  const h = await api.hashPassword("right-answer");
  assert.equal(await api.verifyPassword("right-answer", h), true);
});

test("verifyPassword returns false for wrong password", async () => {
  const h = await api.hashPassword("right-answer");
  assert.equal(await api.verifyPassword("wrong-answer", h), false);
});

test("verifyPassword returns false on empty/null/undefined stored hash", async () => {
  assert.equal(await api.verifyPassword("anything", null),      false);
  assert.equal(await api.verifyPassword("anything", undefined), false);
  assert.equal(await api.verifyPassword("anything", ""),        false);
});

test("verifyPassword accepts legacy SHA256 hashes", async () => {
  const legacy = api.legacySha256("old-password-123");
  assert.equal(legacy.length, 64);
  assert.equal(api.isLegacyHash(legacy), true);
  assert.equal(await api.verifyPassword("old-password-123", legacy), true);
  assert.equal(await api.verifyPassword("wrong",            legacy), false);
});

test("isLegacyHash distinguishes SHA256 from bcrypt", async () => {
  const sha = api.legacySha256("x");
  const bc  = await api.hashPassword("x");
  assert.equal(api.isLegacyHash(sha), true);
  assert.equal(api.isLegacyHash(bc),  false);
  assert.equal(api.isLegacyHash(""),  false);
  assert.equal(api.isLegacyHash(null), false);
  // 64-char but not hex shouldn't match
  assert.equal(api.isLegacyHash("z".repeat(64)), false);
});

// ── JWT sign / verify ────────────────────────────────────────────────────────
test("signToken + verifyToken roundtrip returns the payload fields", () => {
  const token = api.signToken({ id: "u1", email: "a@b.c", role: "admin", site: "Site 1" });
  const out   = api.verifyToken(token);
  assert.equal(out.id,    "u1");
  assert.equal(out.email, "a@b.c");
  assert.equal(out.role,  "admin");
  assert.equal(out.site,  "Site 1");
  assert.equal(typeof out.iat, "number");
});

test("verifyToken returns null for tampered signature", () => {
  const token = api.signToken({ id: "u1", role: "admin" });
  const parts = token.split(".");
  // Flip one char in the signature
  parts[2] = parts[2].slice(0, -1) + (parts[2].endsWith("A") ? "B" : "A");
  assert.equal(api.verifyToken(parts.join(".")), null);
});

test("verifyToken returns null for tampered payload (role-elevation attempt)", () => {
  const token = api.signToken({ id: "u1", role: "viewer" });
  const [h, , s] = token.split(".");
  // Swap viewer → admin in payload without re-signing
  const badBody = Buffer.from(JSON.stringify({ id: "u1", role: "admin", iat: Date.now() })).toString("base64url");
  assert.equal(api.verifyToken(`${h}.${badBody}.${s}`), null);
});

test("verifyToken returns null for malformed tokens", () => {
  assert.equal(api.verifyToken(""),              null);
  assert.equal(api.verifyToken("not-a-token"),   null);
  assert.equal(api.verifyToken("a.b"),           null);
  assert.equal(api.verifyToken(null),            null);
  assert.equal(api.verifyToken(undefined),       null);
});

test("verifyToken rejects tokens older than 8 hours", () => {
  const nineHoursAgo = Date.now() - 9 * 60 * 60 * 1000;
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body   = Buffer.from(JSON.stringify({ id: "u1", iat: nineHoursAgo })).toString("base64url");
  const sig    = crypto.createHmac("sha256", process.env.JWT_SECRET).update(`${header}.${body}`).digest("base64url");
  assert.equal(api.verifyToken(`${header}.${body}.${sig}`), null);
});

// ── Rate limiter ─────────────────────────────────────────────────────────────
// Each test uses a unique email so state from one test doesn't bleed into another.
function freshEvent(ip = "1.2.3.4") {
  return { headers: { "x-nf-client-connection-ip": ip } };
}

test("rateLimitKey combines IP and email (case-insensitive email)", () => {
  const k1 = api.rateLimitKey(freshEvent("10.0.0.1"), "USER@Example.Com");
  const k2 = api.rateLimitKey(freshEvent("10.0.0.1"), "user@example.com");
  const k3 = api.rateLimitKey(freshEvent("10.0.0.2"), "user@example.com");
  assert.equal(k1, k2, "email casing should not affect the key");
  assert.notEqual(k1, k3, "different IPs should produce different keys");
});

test("rateLimitKey falls back to x-forwarded-for, then 'unknown'", () => {
  const k1 = api.rateLimitKey({ headers: { "x-forwarded-for": "7.7.7.7, 8.8.8.8" } }, "a@b.c");
  assert.match(k1, /^7\.7\.7\.7\|/);
  const k2 = api.rateLimitKey({ headers: {} }, "a@b.c");
  assert.match(k2, /^unknown\|/);
});

test("checkLoginRate allows fresh keys", () => {
  const k = `test-fresh-${Math.random()}`;
  assert.equal(api.checkLoginRate(k).allowed, true);
});

test("recordLoginFailure locks after 5 attempts", () => {
  const k = `test-lock-${Math.random()}`;
  for (let i = 0; i < 4; i++) api.recordLoginFailure(k);
  assert.equal(api.checkLoginRate(k).allowed, true, "4 attempts should not lock");
  api.recordLoginFailure(k);
  const r = api.checkLoginRate(k);
  assert.equal(r.allowed, false, "5th attempt should trigger lockout");
  assert.ok(r.retryAfter > 0, "retryAfter should be positive seconds");
  assert.ok(r.retryAfter <= 15 * 60, "retryAfter should be <= lockout window");
});

test("clearLoginRate resets a locked key (simulates successful login)", () => {
  const k = `test-clear-${Math.random()}`;
  for (let i = 0; i < 5; i++) api.recordLoginFailure(k);
  assert.equal(api.checkLoginRate(k).allowed, false);
  api.clearLoginRate(k);
  assert.equal(api.checkLoginRate(k).allowed, true);
});

test("recordLoginFailure tracks IP+email combos independently", () => {
  const kA = `test-iso-A-${Math.random()}`;
  const kB = `test-iso-B-${Math.random()}`;
  for (let i = 0; i < 5; i++) api.recordLoginFailure(kA);
  assert.equal(api.checkLoginRate(kA).allowed, false);
  assert.equal(api.checkLoginRate(kB).allowed, true, "different key should still be allowed");
});
