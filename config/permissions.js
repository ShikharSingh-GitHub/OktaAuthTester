/**
 * Permission Configuration Module
 * Defines permission mappings and role definitions
 */

const PERMISSIONS = {
  READ: "read",
  WRITE: "write",
  DELETE: "delete",
};

const OKTA_GROUPS = {
  READ_USERS: "ReadUsers",
  WRITE_USERS: "WriteUsers",
  DELETE_USERS: "DeleteUsers",
};

// Map API scopes to Okta group names
const SCOPE_TO_GROUP_MAPPING = {
  [PERMISSIONS.READ]: OKTA_GROUPS.READ_USERS,
  [PERMISSIONS.WRITE]: OKTA_GROUPS.WRITE_USERS,
  [PERMISSIONS.DELETE]: OKTA_GROUPS.DELETE_USERS,
};

// Hardcoded users for testing (separate from Okta)
const HARDCODED_USERS = {
  readuser: { password: "readpass", groups: [OKTA_GROUPS.READ_USERS] },
  writeuser: { password: "writepass", groups: [OKTA_GROUPS.WRITE_USERS] },
  deleteuser: { password: "deletepass", groups: [OKTA_GROUPS.DELETE_USERS] },
};

module.exports = {
  PERMISSIONS,
  OKTA_GROUPS,
  SCOPE_TO_GROUP_MAPPING,
  HARDCODED_USERS,
};
