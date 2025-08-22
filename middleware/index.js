const authenticationService = require("../authentication");
const authorizationMiddleware = require("../authorization/middleware");

/**
 * Combined Middleware Exports
 * Main entry point for authentication and authorization middleware
 */

// Export individual middleware functions
const authenticate = authenticationService.middleware();
const authorize = (requiredScope) =>
  authorizationMiddleware.requirePermission(requiredScope);
const addPermissions = authorizationMiddleware.addPermissionsToRequest();

// Export combined middleware for common use cases
const requireRead = [authenticate, authorize("read")];
const requireWrite = [authenticate, authorize("write")];
const requireDelete = [authenticate, authorize("delete")];

module.exports = {
  // Individual middleware
  authenticate,
  authorize,
  addPermissions,

  // Combined middleware
  requireRead,
  requireWrite,
  requireDelete,

  // Direct access to services
  authenticationService,
  authorizationMiddleware,
};
