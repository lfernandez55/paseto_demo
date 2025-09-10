import express from "express";
import cors from "cors";
import { V4 } from "paseto";

/**
 * In production: persist keys (KMS/HSM or files) and rotate them.
 * For demo: generate a fresh keypair at boot.
 */
const privateKey = await V4.generateKey("public");
const publicKey = await privateKey.public();
//const privateKey ="privatekey"
//const publicKey = "publickey"

const ISS = process.env.PASETO_ISS || "urn:auth.example";
const AUD = process.env.PASETO_AUD || "urn:react.example";
const TOKEN_TTL = Number(process.env.TOKEN_TTL_SECONDS || 3600);

const app = express();
app.use(express.json());

// dev CORS: allow Vite/CRA at localhost
app.use(
  cors({
    origin: ["http://localhost:5174","http://localhost:5173", "http://localhost:3000"],
    credentials: false
  })
);

/** Very tiny "users db" */
const USERS = {
  alice: { id: "u1", name: "Alice Admin", roles: ["admin"] },
  tom:   { id: "u2", name: "Tom Teacher", roles: ["teacher"] },
  tina:  { id: "u3", name: "Tina Both", roles: ["admin", "teacher"] }
};

/** Helper: issue a PASETO v4.public token */
async function issueToken({ sub, name, roles }) {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + TOKEN_TTL;

  const payload = {
    sub, name, roles,
    iat: now, exp,
    iss: ISS, aud: AUD
  };

  return await V4.sign(payload, privateKey, { footer: "v4.public" });
}

/** AuthN middleware: verify PASETO and attach claims */
async function authenticate(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const [scheme, token] = auth.split(" ");
    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const claims = await V4.verify(token, publicKey, {
      audience: AUD,
      issuer: ISS
    });

    req.user = claims; // { sub, name, roles, iat, exp, iss, aud }
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

/** AuthZ middleware: require at least one role */
function requireRole(role) {
  return (req, res, next) => {
    const roles = Array.isArray(req.user?.roles) ? req.user.roles : [];
    if (roles.includes(role)) return next();
    return res.status(403).json({ error: "Forbidden: insufficient role" });
  };
}

/** Routes */

// Fake login: pick one of the demo users (alice/tom/tina); password ignored for brevity
app.post("/api/auth/login", async (req, res) => {
  const { username = "" } = req.body;
  const user = USERS[username.toLowerCase()];
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const token = await issueToken({
    sub: user.id,
    name: user.name,
    roles: user.roles
  });

  // Return token + claims so the frontend can show the UI without re-decoding
  return res.json({
    token,
    claims: { sub: user.id, name: user.name, roles: user.roles, iss: ISS, aud: AUD, ttlSeconds: TOKEN_TTL }
  });
});

// Anyone with a valid token
app.get("/api/me", authenticate, (req, res) => {
  res.json({ me: { sub: req.user.sub, name: req.user.name, roles: req.user.roles } });
});

// Admin-only resource
app.get("/api/admin", authenticate, requireRole("admin"), (req, res) => {
  res.json({ message: `Hello ${req.user.name}, you can view admin data.` });
});

// Teacher-only resource
app.get("/api/teacher", authenticate, requireRole("teacher"), (req, res) => {
  res.json({ message: `Hello ${req.user.name}, here is the teacher portal.` });
});

// Health
app.get("/healthz", (_, res) => res.send("ok"));

const port = Number(process.env.PORT || 4000);
app.listen(port, () => {
  console.log(`API listening on http://localhost:${port}`);
});
