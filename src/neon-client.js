// ═══════════════════════════════════════════════════════════════════════════════
// neon-client.js  — drop-in replacement for firebase.js
// Provides the same function signatures as Firebase SDK but calls Neon REST API
// Place in: src/neon-client.js
// ═══════════════════════════════════════════════════════════════════════════════

// ── API base ──────────────────────────────────────────────────────────────────
const BASE = "/.netlify/functions/api";

// ── Token storage ─────────────────────────────────────────────────────────────
const TOKEN_KEY = "hsse_neon_token";
const getToken  = ()  => localStorage.getItem(TOKEN_KEY) || "";
const saveToken = (t) => localStorage.setItem(TOKEN_KEY, t);
const clearToken= ()  => localStorage.removeItem(TOKEN_KEY);

// ── Core fetch ────────────────────────────────────────────────────────────────
async function apiFetch(path, opts = {}, retries = 1) {
  const token = getToken();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);
  try {
    const res = await fetch(`${BASE}/${path}`, {
      ...opts,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...opts.headers,
      },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    clearTimeout(timeoutId);
    const data = await res.json().catch(() => ({}));
    if (res.status === 401) {
      const hadToken = !!getToken();
      clearToken();
      if (hadToken) { window.location.reload(); return null; }
      throw new Error(data?.error || "Invalid email or password");
    }
    if (!res.ok) throw new Error(data?.error || `API error ${res.status}`);
    return data;
  } catch(e) {
    clearTimeout(timeoutId);
    if (retries > 0 && e.name !== "AbortError" && opts.method !== "POST") {
      await new Promise(r => setTimeout(r, 800));
      return apiFetch(path, opts, retries - 1);
    }
    throw e;
  }
}


// ── Real-time simulation ──────────────────────────────────────────────────────
// Firebase onSnapshot → we poll every 15 seconds and call the callback
// Returns an unsubscribe function just like Firebase
const _listeners   = new Map(); // key → { col, callback, timer }
const _cache       = new Map(); // col → last data

function _startPolling(col, callback, docId = null, ref = null) {
  const key = `${col}-${docId||""}-${Date.now()}-${Math.random()}`;
  const poll = async () => {
    try {
      // Build query string from where constraints for server-side filtering
      const constraints = ref?._constraints || [];
      const whereParams = constraints
        .filter(c => c._field && c._op === "==" && c._value)
        .map(c => `${encodeURIComponent(c._field)}=${encodeURIComponent(c._value)}`)
        .join("&");
      const fetchUrl = whereParams ? `${col}?${whereParams}` : col;
      const result = await apiFetch(fetchUrl);
      if (!result) return;

      if (col === "settings") {
        // Settings returns flat {key:value} object
        _cache.set(col, result);
        if (docId) {
          // Specific key lookup: onSnapshot(doc(db,"settings","site01Data"), cb)
          const val = result[docId];
          callback({
            exists: () => val !== undefined && val !== null,
            data:   () => val || {},
            id:     docId,
          });
        } else {
          // Full settings object: onSnapshot(doc(db,"settings","dashboardData"), cb)
          const val = result["dashboardData"] || result;
          callback({
            exists: () => true,
            data:   () => val,
            id:     "dashboardData",
          });
        }
      } else {
        // All other collections return arrays
        const rows = Array.isArray(result) ? result : [];
        const docs = rows.map(r => ({ ...r, _docId: r.id || r._id }));
        _cache.set(col, docs);

        if (docId) {
          // Document listener — find specific doc
          const docData = docs.find(d => d.id === docId || d._id === docId);
          callback({ exists: () => !!docData, data: () => docData || null, id: docId });
        } else {
          // Collection listener — apply where() constraints if any
          const constraints = ref?._constraints || [];
          const filtered = _applyConstraints(docs, constraints);
          // Wrap each doc to look like a Firebase DocumentSnapshot
          const snapDocs = filtered.map(d => ({
            ...d,
            id:     d.id || d._id || d._docId,
            _docId: d.id || d._id || d._docId,
            data:   () => d,          // d.data() returns the flat doc object
            exists: () => true,
          }));
          callback({ docs: snapDocs, forEach: (fn) => snapDocs.forEach(fn) });
        }
      }
    } catch(e) { console.warn(`[Neon] Poll ${col}${docId?"#"+docId:""}:`, e.message); }
  };
  poll();
  const timer = setInterval(poll, 15000);
  // Store the poll fn so refreshAllSnapshots() can force-refresh on demand
  // (Refresh button, tab visibility change, window focus — kills the stale
  // feel when a user returns to the Overview after working in another tab.)
  _listeners.set(key, { col, timer, poll });
  return () => { clearInterval(timer); _listeners.delete(key); };
}

// Force every active onSnapshot listener to re-poll its source immediately.
// Used by the UI Refresh button and by visibilitychange/focus listeners so
// dashboards don't look stale while waiting for the 15-second tick.
export function refreshAllSnapshots() {
  const polls = [];
  _listeners.forEach(l => { if (typeof l.poll === "function") polls.push(l.poll()); });
  return Promise.allSettled(polls);
}

// ── neonDb — mirrors Firestore db object ─────────────────────────────────────
export const neonDb = {}; // placeholder — used as first arg to collection()

// ── neonAuth — mirrors Firebase auth object ───────────────────────────────────
export const neonAuth = {
  currentUser: null,
  _stateListeners: [],
  onAuthStateChanged(callback) {
    this._stateListeners.push(callback);
    // Check token on mount
    const token = getToken();
    if (token) {
      apiFetch("auth/me").then(user => {
        if (user) {
          this.currentUser = user;
          callback(user);
        } else {
          clearToken();
          callback(null);
        }
      }).catch(() => { clearToken(); callback(null); });
    } else {
      callback(null);
    }
    return () => { // unsubscribe
      this._stateListeners = this._stateListeners.filter(l => l !== callback);
    };
  },
  _notify(user) {
    this.currentUser = user;
    this._stateListeners.forEach(l => l(user));
  },
};

// ── Firebase compatibility shim ───────────────────────────────────────────────
// Each function mirrors the Firebase SDK signature exactly so App.js needs
// minimal changes.

function collection(db, col) {
  return col; // just return the collection name string
}

function doc(db, col, id) {
  if (typeof db === "string") {
    // Called as doc(db, "users", uid) — three args
    return { col: db, id: col };
  }
  // Called as doc(db, col, id) — three args with db object first
  return { col, id };
}

// onSnapshot(collection(db, "observations"), callback)
// onSnapshot(doc(db, "settings", "dashboardData"), callback)
function onSnapshot(ref, callback, errCallback) {
  // ref can be: string, {col,id} (doc ref), or {_col, _constraints} (query ref)
  const col   = typeof ref === "string" ? ref
              : ref?._col || ref?.col || null;
  const docId = typeof ref === "string" ? null
              : (ref?.id || null);
  if (!col) { if (errCallback) errCallback(new Error("invalid ref")); return ()=>{}; }
  return _startPolling(col, callback, docId, ref);
}

// addDoc(collection(db, "observations"), data)
async function addDoc(ref, data) {
  const col = typeof ref === "string" ? ref : ref?.col || ref;
  const result = await apiFetch(col, { method: "POST", body: data });
  return { id: result?.id };
}

// deleteDoc(doc(db, "observations", id))
async function deleteDoc(ref) {
  const col = ref.col;
  const id  = ref.id;
  if (!col || !id) throw new Error("deleteDoc: missing col or id");
  await apiFetch(`${col}/${id}`, { method: "DELETE" });
}

// updateDoc(doc(db, "observations", id), data)
async function updateDoc(ref, data) {
  const col = ref.col;
  const id  = ref.id;
  if (!col || !id) throw new Error("updateDoc: missing col or id");
  await apiFetch(`${col}/${id}`, { method: "PUT", body: data });
}

// getDoc(doc(db, "users", uid))
async function getDoc(ref) {
  const col = ref.col;
  const id  = ref.id;
  try {
    const data = await apiFetch(`${col}/${id}`);
    return {
      exists: () => !!data,
      data:   () => data,
      id,
    };
  } catch {
    return { exists: () => false, data: () => null, id };
  }
}

// setDoc(doc(db, "users", uid), data, {merge:true})
async function setDoc(ref, data, opts = {}) {
  const col = ref.col;
  const id  = ref.id;
  if (col === "settings") {
    // Settings: upsert the key with the value object.
    //  • merge:true  → PUT /settings/{id} (server shallow-merges with existing value)
    //  • otherwise   → POST /settings    (server replaces value wholesale)
    // CRITICAL: without the merge branch, writing one sub-key (e.g. {welfare})
    // would wipe every other sub-key (stats, weekly, monthlyState) under the
    // same settings document. See App.js setDoc("settings",<siteKey>,{welfare}).
    if (opts.merge) {
      await apiFetch(`settings/${id}`, { method: "PUT", body: data });
    } else {
      await apiFetch("settings", { method: "POST", body: { [id]: data } });
    }
    return;
  }
  if (opts.merge) {
    // PATCH — merge with existing doc
    await apiFetch(`${col}/${id}`, { method: "PUT", body: data });
  } else {
    // Full replace — POST with specific id
    await apiFetch(col, { method: "POST", body: { ...data, id } });
  }
}

// query() — stores constraints for client-side filtering in onSnapshot
function query(ref, ...constraints) {
  return { _col: typeof ref === "string" ? ref : ref?._col || ref, _constraints: constraints };
}
// where() — stores field/op/value for client-side filtering
function where(field, op, value) { return { _field: field, _op: op, _value: value }; }
function orderBy(field, dir) { return { _orderBy: field, _dir: dir || "asc" }; }
function limit(n) { return { _limit: n }; }

// Apply where constraints to an array of docs
function _applyConstraints(docs, constraints) {
  let result = [...docs];
  for (const c of constraints) {
    if (c._field && c._op && c._value !== undefined) {
      result = result.filter(d => {
        // `??` so falsy-but-present values (0, "", false) still match instead
        // of falling through to the raw-JSONB fallback.
        const val = d[c._field] ?? d.raw?.[c._field];
        if (c._op === "==" || c._op === "===") return val === c._value;
        if (c._op === "!=") return val !== c._value;
        if (c._op === ">")  return val > c._value;
        if (c._op === ">=") return val >= c._value;
        if (c._op === "<")  return val < c._value;
        if (c._op === "<=") return val <= c._value;
        return true;
      });
    }
    if (c._limit) result = result.slice(0, c._limit);
  }
  return result;
}

// ── Auth functions ────────────────────────────────────────────────────────────
async function signInWithEmailAndPassword(authObj, email, password) {
  const data = await apiFetch("auth/login", { method: "POST", body: { email, password } });
  if (data?.token) {
    saveToken(data.token);
    const user = data.user;
    // Shape the user to match Firebase user object
    const firebaseShapedUser = {
      uid:          user.id,
      email:        user.email,
      displayName:  user.name,
      _neonProfile: user,
    };
    neonAuth._notify(firebaseShapedUser);
    return { user: firebaseShapedUser };
  }
  throw new Error(data?.error || "Login failed");
}

async function signOut(authObj) {
  clearToken();
  neonAuth.currentUser = null;
  neonAuth._stateListeners.forEach(l => l(null));
}

async function updatePassword(user, newPassword) {
  await apiFetch("auth/change-password", { method: "POST", body: { password: newPassword } });
}

async function sendPasswordResetEmail(authObj, email) {
  // Neon has no email service built-in — show instruction
  throw new Error("Password reset by email is not available. Please ask your administrator to reset your password in User Management.");
}

async function createUserWithEmailAndPassword(authObj, email, password) {
  // Create user via API — returns a fake Firebase credential shape
  const data = await apiFetch("users", {
    method: "POST",
    body: { email, password, role: "viewer", site: "Site 1", mustChangePassword: true },
  });
  return { user: { uid: data?.id, email } };
}

// ── Export compat object ──────────────────────────────────────────────────────
export const neonCompat = {
  collection, doc, onSnapshot, addDoc, deleteDoc, updateDoc,
  getDoc, setDoc, query, where, orderBy, limit,
  signInWithEmailAndPassword, signOut, updatePassword,
  sendPasswordResetEmail, createUserWithEmailAndPassword,
};

export default neonDb;
