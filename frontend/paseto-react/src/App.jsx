import { useState } from "react";
import { login, setToken, getMe, getAdmin, getTeacher } from "./api";

export default function App() {
  const [username, setUsername] = useState("");
  const [claims, setClaims] = useState(null);
  const [out, setOut] = useState("");

  const doLogin = async (e) => {
    e.preventDefault();
    setOut("");
    try {
      const { token, claims } = await login(username);
      setToken(token);
      setClaims(claims);
      setOut(`Signed in as ${claims.name} [${claims.roles.join(", ")}]`);
    } catch (err) {
      setOut(`Login failed: ${err.message}`);
    }
  };

  const callMe = async () => {
    try {
      const data = await getMe();
      setOut(JSON.stringify(data, null, 2));
    } catch (e) {
      setOut(e.message);
    }
  };

  const callAdmin = async () => {
    try {
      const data = await getAdmin();
      setOut(JSON.stringify(data, null, 2));
    } catch (e) {
      setOut(e.message);
    }
  };

  const callTeacher = async () => {
    try {
      const data = await getTeacher();
      setOut(JSON.stringify(data, null, 2));
    } catch (e) {
      setOut(e.message);
    }
  };

  const signOut = () => {
    setToken("");
    setClaims(null);
    setOut("Signed out.");
  };

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", padding: 24, maxWidth: 720, margin: "0 auto" }}>
      <h1>PASETO Auth Demo</h1>

      <form onSubmit={doLogin} style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input
          placeholder='Try "alice", "tom", or "tina"'
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{ flex: 1, padding: 8 }}
        />
        <button type="submit">Sign In</button>
        <button type="button" onClick={signOut}>Sign Out</button>
      </form>

      <div style={{ marginBottom: 16 }}>
        {claims ? (
          <div>
            <b>Current user:</b> {claims.name} <br />
            <b>Roles:</b> {claims.roles.join(", ")}
          </div>
        ) : (
          <i>No user signed in.</i>
        )}
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <button onClick={callMe}>/api/me (any signed-in user)</button>
        <button onClick={callAdmin}>/api/admin (admin only)</button>
        <button onClick={callTeacher}>/api/teacher (teacher only)</button>
      </div>

      <pre style={{ background: "#111", color: "#0f0", padding: 12, borderRadius: 8, minHeight: 160 }}>
        {out}
      </pre>

      <p style={{ color: "#666" }}>
        Demo users: <b>alice</b> (admin), <b>tom</b> (teacher), <b>tina</b> (admin + teacher).
      </p>
    </div>
  );
}
