// Role-based authorization. Use after `authenticate`, which attaches
// req.user (including req.user.role) from the verified JWT payload.
//
//   router.get("/api/admin/users", authenticate, authorize("ADMIN"), handler)
export function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      // Should never happen if `authenticate` ran first, but fail safely.
      return res
        .status(401)
        .json({ error: "Access denied. No token provided." });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error:
          "Access denied. You do not have permission to perform this action.",
        requiredRoles: allowedRoles,
        yourRole: req.user.role,
      });
    }

    next();
  };
}
