require("dotenv").config();
const OktaJwtVerifier = require("@okta/jwt-verifier");
const axios = require("axios");
const basicAuth = require("basic-auth");

// ---- Okta URL helpers ----
function getOrgBaseUrl() {
  const explicit = process.env.OKTA_ORG_URL;
  if (explicit) return explicit.replace(/\/$/, "");
  const issuer = process.env.OKTA_ISSUER;
  if (!issuer) return undefined;
  try {
    const url = new URL(issuer);
    return `${url.protocol}//${url.host}`; // strip any /oauth2/* path
  } catch (_) {
    return undefined;
  }
}

function buildOktaUrls() {
  const orgBase = getOrgBaseUrl();
  const authn =
    process.env.OKTA_AUTHN_URL ||
    (orgBase ? `${orgBase}/api/v1/authn` : undefined);
  const api =
    process.env.OKTA_API_URL || (orgBase ? `${orgBase}/api/v1` : undefined);
  return { orgBase, authn, api };
}

function resolveOktaUrl(href, orgBase) {
  if (!href) return undefined;
  if (/^https?:\/\//i.test(href)) return href;
  if (!orgBase) return undefined;
  if (href.startsWith("/")) return `${orgBase}${href}`;
  return `${orgBase}/${href}`;
}

// Map scopes to Okta group names for Basic Auth (align with Okta groups)
const check = {
  read: "ReadUsers",
  write: "WriteUsers",
  delete: "DeleteUsers",
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

    // Validate required env upfront for Okta lookups
    const { orgBase, authn, api } = buildOktaUrls();
    if (!authn) {
      return res.status(500).json({
        error: "Server misconfiguration",
        details: "Missing OKTA_AUTHN_URL or OKTA_ISSUER",
      });
    }

    // Hardcoded users for testing
    const hardcodedUsers = {
      readuser: { password: "readpass", groups: ["ReadUsers"] },
      writeuser: { password: "writepass", groups: ["WriteUsers"] },
      deleteuser: { password: "deletepass", groups: ["DeleteUsers"] },
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

    // Fallback to Okta AuthN API for other users (handles MFA incl. Okta Verify Push)
    try {
      const baseHeaders = { headers: { "Content-Type": "application/json" } };
      const initial = await axios.post(
        authn,
        { username: credentials.name, password: credentials.pass },
        baseHeaders
      );

      const tx = initial.data;
      if (!tx) return res.status(401).json({ error: "Authentication failed" });

      // Helper to sleep between polls
      const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

      // Poll Okta Verify Push until approved or timeout
      const pollPush = async (
        verifyHref,
        stateToken,
        timeoutMs = 90000,
        intervalMs = 3000
      ) => {
        const verifyUrl = resolveOktaUrl(verifyHref, orgBase);
        if (!verifyUrl) throw new Error("Invalid verify URL");
        const start = Date.now();
        let last;
        while (Date.now() - start < timeoutMs) {
          const resp = await axios.post(verifyUrl, { stateToken }, baseHeaders);
          last = resp.data;
          const factorResult = last.factorResult;
          const status = last.status;
          if (status === "SUCCESS" || factorResult === "SUCCESS") return last;
          if (factorResult === "REJECTED" || factorResult === "TIMEOUT") {
            const errMsg =
              factorResult === "REJECTED"
                ? "MFA push rejected"
                : "MFA push timed out";
            throw new Error(errMsg);
          }
          await sleep(intervalMs);
        }
        const msg = last?.factorResult || last?.status || "MFA push timeout";
        throw new Error(`MFA push did not complete: ${msg}`);
      };

      let finalTx = tx;
      // Capture user id early in case final response omits it
      const initialUserId = tx?._embedded?.user?.id;

      if (tx.status === "SUCCESS") {
        // password-only success (no MFA)
        finalTx = tx;
      } else if (
        tx.status === "MFA_REQUIRED" ||
        tx.status === "MFA_CHALLENGE"
      ) {
        const stateToken = tx.stateToken;
        const factors = tx._embedded?.factors || [];
        // Prefer Okta Verify Push factor
        const push = factors.find(
          (f) =>
            f.factorType === "push" &&
            f.provider &&
            (f.provider === "OKTA" || f.provider === "OKTA_VERIFY")
        );

        if (push && push._links?.verify?.href) {
          finalTx = await pollPush(push._links.verify.href, stateToken);
        } else {
          return res.status(401).json({
            error: "MFA required but no Push factor available",
            details:
              "Enroll Okta Verify Push for this user or disable MFA for testing.",
          });
        }
      } else {
        return res
          .status(401)
          .json({ error: `AuthN failed: ${tx.status || "UNKNOWN"}` });
      }

      const successUserId = finalTx?._embedded?.user?.id || initialUserId;
      if (!successUserId)
        return res
          .status(401)
          .json({ error: "Unable to resolve user after authentication" });

      if (!api) {
        return res.status(500).json({
          error: "Server misconfiguration",
          details: "Missing OKTA_API_URL or OKTA_ISSUER",
        });
      }
      if (!process.env.OKTA_API_TOKEN) {
        return res.status(500).json({
          error: "Server misconfiguration",
          details: "Missing OKTA_API_TOKEN",
        });
      }
      const groupsResponse = await axios.get(
        `${api}/users/${successUserId}/groups`,
        { headers: { Authorization: `SSWS ${process.env.OKTA_API_TOKEN}` } }
      );

      const userGroups = (groupsResponse.data || [])
        .map((g) => g.profile?.name)
        .filter(Boolean);

      req.user = {
        type: "basic",
        username: credentials.name,
        groups: userGroups,
      };
      return next();
    } catch (err) {
      const details = err.response?.data || err.message;
      console.error("Basic Auth (Okta) failed:", details);
      return res.status(401).json({ error: "Authentication failed", details });
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
