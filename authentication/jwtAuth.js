const OktaJwtVerifier = require("@okta/jwt-verifier");
const oktaConfig = require("../config/okta");

/**
 * JWT Authentication Module
 * Handles Bearer token authentication using Okta JWT verification
 */

class JwtAuthenticator {
  constructor() {
    // Initialize JWT verifier only if Okta config is valid
    const validation = oktaConfig.validate();
    if (validation.isValid) {
      this.oktaJwtVerifier = new OktaJwtVerifier({
        clientId: oktaConfig.clientId,
        issuer: oktaConfig.issuer,
        assertClaims: { aud: oktaConfig.audience },
      });
    } else {
      console.warn(
        "JWT Authenticator: Okta configuration incomplete:",
        validation.missing
      );
      this.oktaJwtVerifier = null;
    }
  }

  /**
   * Authenticate JWT Bearer token
   * @param {string} authHeader - Authorization header value
   * @returns {Object} User object with JWT claims
   */
  async authenticate(authHeader) {
    if (!this.oktaJwtVerifier) {
      throw new Error(
        "JWT authentication not configured. Check Okta settings."
      );
    }

    // Extract token from "Bearer <token>"
    const token = authHeader.split(" ")[1];
    if (!token) {
      throw new Error("No token provided in Bearer authorization");
    }

    try {
      const jwt = await this.oktaJwtVerifier.verifyAccessToken(
        token,
        oktaConfig.audience
      );

      return {
        type: "client",
        source: "jwt",
        claims: jwt.claims,
        scopes: jwt.claims.scp || [],
      };
    } catch (error) {
      throw new Error(`Invalid or expired token: ${error.message}`);
    }
  }

  /**
   * Check if JWT authenticator is properly configured
   * @returns {boolean} True if configured
   */
  isConfigured() {
    return this.oktaJwtVerifier !== null;
  }
}

module.exports = new JwtAuthenticator();
