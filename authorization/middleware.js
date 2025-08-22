const permissionService = require("./permissions");

/**
 * Authorization Middleware
 * Handles access control after authentication
 */

class AuthorizationMiddleware {
  /**
   * Create authorization middleware for specific permission
   * @param {string} requiredScope - Required permission scope
   * @returns {Function} Express middleware function
   */
  requirePermission(requiredScope) {
    return (req, res, next) => {
      try {
        // Check if user is authenticated
        if (!req.user) {
          return res.status(401).json({
            error: "Authentication required",
            details: "No authenticated user found",
          });
        }

        // Check if user has required permission
        const hasPermission = permissionService.hasPermission(
          req.user,
          requiredScope
        );

        if (!hasPermission) {
          const userType =
            req.user.type === "basic" ? "Basic Auth" : "JWT Bearer";
          return res.status(403).json({
            error: `Insufficient scope (${userType})`,
            details: `Required permission: ${requiredScope}`,
            userPermissions: permissionService.getUserPermissions(req.user),
          });
        }

        next();
      } catch (error) {
        console.error("Authorization error:", error.message);
        res.status(500).json({
          error: "Authorization error",
          details: error.message,
        });
      }
    };
  }

  /**
   * Middleware to add user permissions to request object
   * @returns {Function} Express middleware function
   */
  addPermissionsToRequest() {
    return (req, res, next) => {
      if (req.user) {
        req.userPermissions = permissionService.getUserPermissions(req.user);
      }
      next();
    };
  }
}

module.exports = new AuthorizationMiddleware();
