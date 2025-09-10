const API_BASE = "http://localhost:4000";

export function setToken(token) {
  localStorage.setItem("paseto_token", token || "");
}
export function getToken() {
  return localStorage.getItem("paseto_token") || "";
}

async function api(path, options = {}) {
  const token = getToken();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

export const login = (username) =>
  api("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username })
  });

export const getMe = () => api("/api/me");
export const getAdmin = () => api("/api/admin");
export const getTeacher = () => api("/api/teacher");
