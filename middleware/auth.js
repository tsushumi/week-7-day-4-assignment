import jwt from "jsonwebtoken";

// Verifies a Bearer token from the Authorization header and attaches the
// decoded payload ({ userId, email, role, iat, exp }) to req.user.
export function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ error: "Access denied. No token provided." });
  }

  const token = authHeader.slice("Bearer ".length).trim();

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ error: "Token has expired. Please log in again." });
      }
      return res.status(401).json({ error: "Invalid token." });
    }

    req.user = decoded;
    next();
  });
}

// Cookie-based variant for the bonus CSRF flow: reads the JWT from an
// httpOnly cookie instead of the Authorization header.
export function authenticateCookie(req, res, next) {
  const token = req.cookies?.token;

  if (!token) {
    return res
      .status(401)
      .json({ error: "Access denied. No token provided." });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res
          .status(401)
          .json({ error: "Token has expired. Please log in again." });
      }
      return res.status(401).json({ error: "Invalid token." });
    }

    req.user = decoded;
    next();
  });
}
