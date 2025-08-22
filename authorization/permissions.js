const { SCOPE_TO_GROUP_MAPPING } = require("../config/permissions");

/**
 * Permission Service
 * Handles permission checking logic for different user types
 */

class PermissionService {
  /**
   * Check if user has required permission
   * @param {Object} user - Authenticated user object
   * @param {string} requiredScope - Required permission scope
   * @returns {boolean} True if user has permission
   */
  hasPermission(user, requiredScope) {
    if (!user || !requiredScope) {
      return false;
    }

    // Handle Basic Auth users (check groups)
    if (user.type === "basic") {
      return this.checkGroupPermission(user, requiredScope);
    }

    // Handle JWT Bearer users (check scopes)
    if (user.type === "client") {
      return this.checkScopePermission(user, requiredScope);
    }

    return false;
  }

  /**
   * Check group-based permissions for Basic Auth users
   * @param {Object} user - User object with groups
   * @param {string} requiredScope - Required permission scope
   * @returns {boolean} True if user has permission
   */
  checkGroupPermission(user, requiredScope) {
    const requiredGroup = SCOPE_TO_GROUP_MAPPING[requiredScope];
    if (!requiredGroup) {
      console.warn(`Unknown permission scope: ${requiredScope}`);
      return false;
    }

    return user.groups && user.groups.includes(requiredGroup);
  }

  /**
   * Check scope-based permissions for JWT users
   * @param {Object} user - User object with claims
   * @param {string} requiredScope - Required permission scope
   * @returns {boolean} True if user has permission
   */
  checkScopePermission(user, requiredScope) {
    const scopes = user.claims?.scp || user.scopes || [];
    return Array.isArray(scopes) && scopes.includes(requiredScope);
  }

  /**
   * Get user's permissions summary
   * @param {Object} user - Authenticated user object
   * @returns {Object} Permission summary
   */
  getUserPermissions(user) {
    if (!user) {
      return { permissions: [], type: "none" };
    }

    if (user.type === "basic") {
      return {
        type: "basic",
        source: user.source || "unknown",
        groups: user.groups || [],
        permissions: this.getPermissionsFromGroups(user.groups || []),
      };
    }

    if (user.type === "client") {
      const scopes = user.claims?.scp || user.scopes || [];
      return {
        type: "client",
        source: user.source || "jwt",
        scopes: scopes,
        permissions: scopes,
      };
    }

    return { permissions: [], type: user.type || "unknown" };
  }

  /**
   * Convert groups to permissions
   * @param {Array} groups - User groups
   * @returns {Array} Corresponding permissions
   */
  getPermissionsFromGroups(groups) {
    const permissions = [];
    for (const [scope, group] of Object.entries(SCOPE_TO_GROUP_MAPPING)) {
      if (groups.includes(group)) {
        permissions.push(scope);
      }
    }
    return permissions;
  }
}

module.exports = new PermissionService();
