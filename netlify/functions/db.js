// Shared Neon connection pool — imported by all functions
const { Pool } = require("pg");

let pool;
const getPool = () => {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5,
      idleTimeoutMillis: 30000,
    });
  }
  return pool;
};

// Standard JSON response helpers
const ok  = (data, status=200) => ({ statusCode:status, headers:cors(), body:JSON.stringify(data) });
const err = (msg,  status=500) => ({ statusCode:status, headers:cors(), body:JSON.stringify({error:msg}) });
const cors = () => ({
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
});

module.exports = { getPool, ok, err, cors };
