/**
 * TradeVault — Auth Backend
 * ─────────────────────────────────────────────
 * Stack : Node.js + Express + better-sqlite3 + jose (JWT)
 *
 * Install:
 *   npm install express better-sqlite3 jose google-auth-library cors dotenv
 *
 * .env (create this file):
 *   GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
 *   GOOGLE_CLIENT_SECRET=your_client_secret
 *   JWT_SECRET=change_this_to_a_long_random_string_at_least_32_chars
 *   PORT=3000
 *   FRONTEND_URL=http://localhost:5500  (or wherever your login.html is served)
 *
 * Run:
 *   node server.js
 *
 * Endpoints:
 *   POST /auth/google/callback   — receives Google token / profile, returns session JWT
 *   GET  /user/me                — returns authenticated user data (requires Bearer token)
 *   POST /auth/logout            — clears server-side session flag
 *   GET  /admin/users            — lists all users (protected, for dev/demo only)
 * ─────────────────────────────────────────────
 */

"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const { SignJWT, jwtVerify } = require("jose");
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");
const path = require("path");

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const JWT_SECRET_RAW =
  process.env.JWT_SECRET || "dev_secret_change_me_in_production";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const JWT_EXPIRES_IN = "7d"; // session lifetime

if (!GOOGLE_CLIENT_ID) {
  console.warn(
    "⚠  GOOGLE_CLIENT_ID not set in .env — token verification will be skipped in demo mode",
  );
}

// Encode secret for jose
const JWT_SECRET = new TextEncoder().encode(JWT_SECRET_RAW.padEnd(32, "!"));

// ─── DATABASE ─────────────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, "tradevault.db"), {
  // verbose: console.log, // uncomment to log SQL queries
});

// Enable WAL mode for better concurrency
db.pragma("journal_mode = WAL");

// ── Schema ──
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    google_id   TEXT    UNIQUE NOT NULL,
    email       TEXT    UNIQUE NOT NULL,
    name        TEXT    NOT NULL,
    picture     TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    jti         TEXT    UNIQUE NOT NULL,       -- JWT ID (for revocation)
    ip          TEXT,
    user_agent  TEXT,
    login_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT    NOT NULL DEFAULT (datetime('now')),
    revoked     INTEGER NOT NULL DEFAULT 0
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_jti     ON sessions(jti);
  CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
`);

// ── Prepared statements ──
const stmts = {
  upsertUser: db.prepare(`
    INSERT INTO users (google_id, email, name, picture, updated_at)
    VALUES (@google_id, @email, @name, @picture, datetime('now'))
    ON CONFLICT(google_id) DO UPDATE SET
      email      = excluded.email,
      name       = excluded.name,
      picture    = excluded.picture,
      updated_at = datetime('now')
    RETURNING *
  `),
  getUserById: db.prepare(`SELECT * FROM users WHERE id = ?`),
  getUserByEmail: db.prepare(`SELECT * FROM users WHERE email = ?`),
  createSession: db.prepare(`
    INSERT INTO sessions (user_id, jti, ip, user_agent)
    VALUES (@user_id, @jti, @ip, @user_agent)
  `),
  touchSession: db.prepare(`
    UPDATE sessions SET last_seen = datetime('now') WHERE jti = ?
  `),
  revokeSession: db.prepare(`
    UPDATE sessions SET revoked = 1 WHERE jti = ?
  `),
  getSession: db.prepare(`
    SELECT * FROM sessions WHERE jti = ? AND revoked = 0
  `),
  listUsers: db.prepare(`
    SELECT id, google_id, email, name, picture, created_at, updated_at FROM users ORDER BY created_at DESC
  `),
  getUserSessions: db.prepare(`
    SELECT * FROM sessions WHERE user_id = ? ORDER BY login_at DESC LIMIT 10
  `),
};

// ─── EXPRESS SETUP ────────────────────────────────────────────────────────────
const app = express();

app.use(
  cors({
    origin: [FRONTEND_URL, "http://127.0.0.1:3000", "http://localhost:3000"],
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(express.json());

// Request logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ─── HELPERS ──────────────────────────────────────────────────────────────────

/** Mint a signed JWT for a user */
async function mintJWT(user, jti) {
  return new SignJWT({ sub: String(user.id), email: user.email, jti })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(JWT_EXPIRES_IN)
    .sign(JWT_SECRET);
}

/** Verify a JWT and return its payload, or null */
async function verifyJWT(token) {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return payload;
  } catch {
    return null;
  }
}

/** Extract Bearer token from Authorization header */
function extractBearer(req) {
  const auth = req.headers.authorization || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim();
  return null;
}

/** Verify Google ID token via Google Auth Library */
async function verifyGoogleIdToken(idToken) {
  if (!GOOGLE_CLIENT_ID) return null;
  const client = new OAuth2Client(GOOGLE_CLIENT_ID);
  try {
    const ticket = await client.verifyIdToken({
      idToken,
      audience: GOOGLE_CLIENT_ID,
    });
    return ticket.getPayload(); // { sub, email, name, picture, ... }
  } catch (err) {
    console.error("Google token verification failed:", err.message);
    return null;
  }
}

/** Authentication middleware */
async function requireAuth(req, res, next) {
  const token = extractBearer(req);
  if (!token) return res.status(401).json({ error: "No token provided" });

  const payload = await verifyJWT(token);
  if (!payload)
    return res.status(401).json({ error: "Invalid or expired token" });

  // Check session is not revoked
  const session = stmts.getSession.get(payload.jti);
  if (!session)
    return res.status(401).json({ error: "Session revoked or not found" });

  // Attach user to request
  const user = stmts.getUserById.get(Number(payload.sub));
  if (!user) return res.status(401).json({ error: "User not found" });

  req.user = user;
  req.jti = payload.jti;
  req.payload = payload;
  next();
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────

/** Health check */
app.get("/", (_req, res) => {
  res.json({
    service: "TradeVault Auth API",
    status: "ok",
    time: new Date().toISOString(),
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /auth/google/callback
//
// Accepts either:
//   { id_token: "..." }              — Google One Tap / GSI flow
//   { profile: { sub, email, ... } } — access-token fallback (client-side userinfo)
//
// Returns: { user, session_token }
// ──────────────────────────────────────────────────────────────────────────────
app.post("/auth/google/callback", async (req, res) => {
  try {
    let googleId, email, name, picture;

    if (req.body.id_token) {
      // ── Verify ID token server-side (most secure) ──
      const payload = await verifyGoogleIdToken(req.body.id_token);
      if (!payload) {
        return res.status(401).json({ error: "Invalid Google ID token" });
      }
      googleId = payload.sub;
      email = payload.email;
      name = payload.name;
      picture = payload.picture;
    } else if (req.body.profile) {
      // ── Client-side userinfo profile (fallback) ──
      // NOTE: In production, always prefer server-side token verification.
      const p = req.body.profile;
      googleId = p.sub;
      email = p.email;
      name = p.name;
      picture = p.picture;

      if (!googleId || !email) {
        return res.status(400).json({ error: "Missing profile fields" });
      }
    } else {
      return res.status(400).json({ error: "Provide id_token or profile" });
    }

    // ── Upsert user in DB ──
    const user = stmts.upsertUser.get({
      google_id: googleId,
      email,
      name,
      picture,
    });

    // ── Create session ──
    const jti = crypto.randomUUID();
    stmts.createSession.run({
      user_id: user.id,
      jti,
      ip: req.ip || req.socket.remoteAddress || null,
      user_agent: req.headers["user-agent"] || null,
    });

    // ── Mint JWT ──
    const sessionToken = await mintJWT(user, jti);

    console.log(`✅ Login: ${email} (id=${user.id})`);

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        picture: user.picture,
      },
      session_token: sessionToken,
    });
  } catch (err) {
    console.error("/auth/google/callback error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /user/me  (requires Bearer token)
// Returns current user data + session info
// ──────────────────────────────────────────────────────────────────────────────
app.get("/user/me", requireAuth, (req, res) => {
  // Touch last_seen
  stmts.touchSession.run(req.jti);

  const sessions = stmts.getUserSessions.all(req.user.id);

  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      name: req.user.name,
      picture: req.user.picture,
      created_at: req.user.created_at,
      updated_at: req.user.updated_at,
    },
    sessions: sessions.map((s) => ({
      login_at: s.login_at,
      last_seen: s.last_seen,
      ip: s.ip,
    })),
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// POST /auth/logout  (requires Bearer token)
// Revokes the current session JWT
// ──────────────────────────────────────────────────────────────────────────────
app.post("/auth/logout", requireAuth, (req, res) => {
  stmts.revokeSession.run(req.jti);
  console.log(`👋 Logout: ${req.user.email}`);
  res.json({ success: true, message: "Session revoked" });
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /admin/users  (demo only — add proper admin auth in production)
// Returns all registered users
// ──────────────────────────────────────────────────────────────────────────────
app.get("/admin/users", requireAuth, (req, res) => {
  const users = stmts.listUsers.all();
  res.json({ count: users.length, users });
});

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 TradeVault Auth Server`);
  console.log(`   Listening on : http://localhost:${PORT}`);
  console.log(`   Database     : ${path.join(__dirname, "tradevault.db")}`);
  console.log(`   Frontend URL : ${FRONTEND_URL}`);
  console.log(
    `   Google ID    : ${GOOGLE_CLIENT_ID ? GOOGLE_CLIENT_ID.slice(0, 20) + "…" : "⚠ NOT SET"}`,
  );
  console.log(`\n   Endpoints:`);
  console.log(`   POST /auth/google/callback`);
  console.log(`   GET  /user/me`);
  console.log(`   POST /auth/logout`);
  console.log(`   GET  /admin/users\n`);
});
