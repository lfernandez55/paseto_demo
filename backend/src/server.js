// src/server.js
import express from "express";
import cors from "cors";
import { V4 } from "paseto";
import { createPublicKey } from "node:crypto";

/**
 * DEV KEYS (demo):
 * In production, load from KMS/HSM or disk and rotate keys.
 * For this demo we just create a new Ed25519 keypair at boot.
 */
const privateKey = await V4.generateKey("public"); // Ed25519 private key (KeyObject)
const publicKey  = createPublicKey(privateKey);     // <- derive the public key

/** Config: single source of truth for iss/aud/ttl */
function envString(name, fallback) {
  const v = (process.env[name] ?? fallback ?? "").trim();
  if (!v) console.warn(`[warn] ${name} not set; using "${v}"`);
  return v;
}
const ISS = envString("PASETO_ISS", "urn:auth.example");   // must match at sign & verify
const AUD = envString("PASETO_AUD", "urn:react.example");  // must match at sign & verify
const TOKEN_TTL = Number(process.env.TOKEN_TTL_SECONDS || 3600);

console.log(`[auth] Using ISS="${ISS}" AUD="${AUD}" TTL=${TOKEN_TTL}s`);

const app = express();
app.use(express.json());

// Dev CORS: allow Vite/CRA at localhost
app.use(
  cors({
    origin: ["http://localhost:5174","http://localhost:5173", "http://localhost:3000"],
    credentials: false
  })
);

/** Tiny in-memory "users db" */
const USERS = {
  alice: { id: "u1", name: "Alice Admin", roles: ["admin"] },
  tom:   { id: "u2", name: "Tom Teacher", roles: ["teacher"] },
  tina:  { id: "u3", name: "Tina Both", roles: ["admin", "teacher"] }
};

/** Issue a PASETO v4.public token */
/** Issue a PASETO v4.public token */
async function issueToken({ sub, name, roles }) {
  const now = new Date();
  const payload = {
    sub,
    name,
    roles,
    iat: now.toISOString(),                                             // string
    exp: new Date(now.getTime() + TOKEN_TTL * 1000).toISOString(),      // string
    iss: ISS,
    aud: AUD
  };

  return await V4.sign(payload, privateKey, { footer: "v4.public" });
}

/** AuthN: verify PASETO and attach claims */
async function authenticate(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const [scheme, token] = auth.split(" ");
    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const claims = await V4.verify(token, publicKey, {
      audience: AUD,
      issuer: ISS,
      clockTolerance: "60s"
    });

    req.user = claims; // { sub, name, roles, iat, exp, iss, aud }
    next();
  } catch (err) {
    console.error("PASETO verify failed:", err?.message || err);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

/** AuthZ: require a role */
function requireRole(role) {
  return (req, res, next) => {
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    if (roles.includes(role)) return next();
    return res.status(403).json({ error: "Forbidden: insufficient role" });
  };
}

/** Routes */

// Fake login: username picks the demo user (alice/tom/tina); password ignored
app.post("/api/auth/login", async (req, res) => {
  const { username = "" } = req.body || {};
  const user = USERS[username.toLowerCase()];
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const token = await issueToken({
    sub: user.id,
    name: user.name,
    roles: user.roles
  });

  return res.json({
    token,
    claims: {
      sub: user.id,
      name: user.name,
      roles: user.roles,
      iss: ISS,
      aud: AUD,
      ttlSeconds: TOKEN_TTL
    }
  });
});

// Any signed-in user
app.get("/api/me", authenticate, (req, res) => {
  res.json({ me: { sub: req.user.sub, name: req.user.name, roles: req.user.roles } });
});

// Admin-only
app.get("/api/admin", authenticate, requireRole("admin"), (req, res) => {
  res.json({ message: `Hello ${req.user.name}, you can view admin data.` });
});

// Teacher-only
app.get("/api/teacher", authenticate, requireRole("teacher"), (req, res) => {
  res.json({ message: `Hello ${req.user.name}, here is the teacher portal.` });
});

// Debug helper (temporary): compare server ISS/AUD with token's claims
app.post("/api/debug/decode", async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "token required" });
  try {
    // Verify signature only (no iss/aud enforcement here)
    const claims = await V4.verify(token, publicKey);
    res.json({
      serverExpects: { ISS, AUD },
      tokenClaims: {
        iss: claims.iss, aud: claims.aud, exp: claims.exp,
        sub: claims.sub, roles: claims.roles, iat: claims.iat
      }
    });
  } catch (e) {
    res.status(200).json({ valid: false, reason: String(e?.message || e) });
  }
});

// Health
app.get("/healthz", (_, res) => res.send("ok"));

const port = Number(process.env.PORT || 4000);
app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});
