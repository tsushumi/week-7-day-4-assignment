import crypto from "crypto";

// In-memory map of userId -> current CSRF token. In a real app with
// server-side sessions this would be keyed by session ID instead of
// userId; here the httpOnly auth cookie already gives us a stable
// per-user key once authenticateCookie has run.
export const csrfTokens = new Map();

export function generateCsrfToken(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  csrfTokens.set(userId, token);
  return token;
}

const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// Must run after authenticateCookie, so req.user is available.
export function csrfProtection(req, res, next) {
  if (!STATE_CHANGING_METHODS.has(req.method)) {
    return next();
  }

  const headerToken = req.headers["x-csrf-token"];
  const expectedToken = csrfTokens.get(req.user?.userId);

  if (!headerToken || !expectedToken || headerToken !== expectedToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  next();
}
