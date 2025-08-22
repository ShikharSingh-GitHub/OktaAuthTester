const authorizationMiddleware = require("./middleware");
const permissionService = require("./permissions");

/**
 * Authorization Module Main Export
 * Provides centralized access to authorization functionality
 */

module.exports = {
  middleware: authorizationMiddleware,
  permissions: permissionService,

  // Convenience exports
  requirePermission: authorizationMiddleware.requirePermission.bind(
    authorizationMiddleware
  ),
  hasPermission: permissionService.hasPermission.bind(permissionService),
  getUserPermissions:
    permissionService.getUserPermissions.bind(permissionService),
};
