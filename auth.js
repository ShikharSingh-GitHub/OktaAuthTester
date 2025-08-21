require("dotenv").config();
const OktaJwtVerifier = require("@okta/jwt-verifier");
const axios = require("axios");
const basicAuth = require("basic-auth");

// Map scopes to Okta group names for Basic Auth
const check = {
  read: "read-user",
  write: "write-user",
  delete: "delete-user",
};

const oktaJwtVerifier = new OktaJwtVerifier({
  clientId: process.env.OKTA_CLIENT_ID,
  issuer: process.env.OKTA_ISSUER,
  assertClaims: { aud: process.env.OKTA_AUDIENCE },
});

// Authentication middleware
async function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader)
    return res.status(401).json({ error: "Missing authorization header" });

  // ---- Basic Auth ----
  if (authHeader.startsWith("Basic ")) {
    const credentials = basicAuth.parse(authHeader);
    if (!credentials)
      return res.status(401).json({ error: "Invalid Basic credentials" });

    // Hardcoded users for testing
    const hardcodedUsers = {
      readuser: { password: "readpass", groups: ["read-user"] },
      writeuser: { password: "writepass", groups: ["write-user"] },
      deleteuser: { password: "deletepass", groups: ["delete-user"] },
    };
    const user = hardcodedUsers[credentials.name];
    if (user && credentials.pass === user.password) {
      req.user = {
        type: "basic",
        username: credentials.name,
        groups: user.groups,
      };
      return next();
    }

    // Fallback to Okta AuthN API for other users
    try {
      const authResponse = await axios.post(
        `${process.env.OKTA_AUTHN_URL}`,
        { username: credentials.name, password: credentials.pass },
        { headers: { "Content-Type": "application/json" } }
      );

      if (!authResponse.data || authResponse.data.status !== "SUCCESS") {
        return res.status(401).json({ error: "Invalid Okta credentials" });
      }

      const userId = authResponse.data._embedded.user.id;

      const groupsResponse = await axios.get(
        `${process.env.OKTA_API_URL}/users/${userId}/groups`,
        { headers: { Authorization: `SSWS ${process.env.OKTA_API_TOKEN}` } }
      );

      const userGroups = groupsResponse.data.map((g) => g.profile.name);

      req.user = {
        type: "basic",
        username: credentials.name,
        groups: userGroups,
      };
      return next();
    } catch (err) {
      console.error("Basic Auth failed:", err.response?.data || err.message);
      return res.status(401).json({ error: "Authentication failed" });
    }
  }

  // ---- Bearer JWT ----
  else if (authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    try {
      const jwt = await oktaJwtVerifier.verifyAccessToken(
        token,
        process.env.OKTA_AUDIENCE
      );
      req.user = {
        type: "client",
        claims: jwt.claims,
      };
      return next();
    } catch (err) {
      console.warn(
        `[AUTH FAILURE] ${req.ip} attempted ${req.method} ${req.originalUrl} → ${err.message}`
      );
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  } else {
    return res.status(401).json({ error: "Unsupported auth type" });
  }
}

// Scope / role-based authorization
function authorize(requiredScope) {
  return (req, res, next) => {
    // Basic Auth: check Okta groups
    if (req.user.type === "basic") {
      const groupName = check[requiredScope];
      if (req.user.groups?.includes(groupName)) return next();
      return res.status(403).json({ error: "Insufficient scope (Basic Auth)" });
    }

    // JWT Bearer: check scp claim
    const scopes = req.user.claims?.scp || [];
    if (Array.isArray(scopes) && scopes.includes(requiredScope)) return next();

    return res.status(403).json({ error: "Insufficient scope" });
  };
}

module.exports = { authenticate, authorize };
