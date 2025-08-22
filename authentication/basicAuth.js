const basicAuth = require("basic-auth");
const axios = require("axios");
const oktaConfig = require("../config/okta");
const { HARDCODED_USERS } = require("../config/permissions");

/**
 * Basic Authentication Module
 * Handles Basic Auth with both hardcoded users and Okta integration
 */

class BasicAuthenticator {
  /**
   * Authenticate user with Basic Auth credentials
   * @param {string} authHeader - Authorization header value
   * @returns {Object|null} User object or null if authentication fails
   */
  async authenticate(authHeader) {
    const credentials = basicAuth.parse(authHeader);
    if (!credentials) {
      throw new Error("Invalid Basic credentials");
    }

    // Try hardcoded users first (for testing)
    const hardcodedUser = await this.authenticateHardcodedUser(credentials);
    if (hardcodedUser) {
      return hardcodedUser;
    }

    // Fallback to Okta authentication
    return await this.authenticateOktaUser(credentials);
  }

  /**
   * Authenticate against hardcoded users
   * @param {Object} credentials - Username and password
   * @returns {Object|null} User object or null
   */
  async authenticateHardcodedUser(credentials) {
    const user = HARDCODED_USERS[credentials.name];
    if (user && credentials.pass === user.password) {
      return {
        type: "basic",
        source: "hardcoded",
        username: credentials.name,
        groups: user.groups,
      };
    }
    return null;
  }

  /**
   * Authenticate against Okta
   * @param {Object} credentials - Username and password
   * @returns {Object} User object with Okta groups
   */
  async authenticateOktaUser(credentials) {
    // Validate Okta configuration
    const validation = oktaConfig.validate();
    if (!validation.isValid) {
      throw new Error(
        `Okta misconfiguration: Missing ${validation.missing.join(", ")}`
      );
    }

    const baseHeaders = { headers: { "Content-Type": "application/json" } };

    // Initial authentication request
    const initial = await axios.post(
      oktaConfig.authnUrl,
      { username: credentials.name, password: credentials.pass },
      baseHeaders
    );

    const tx = initial.data;
    if (!tx) {
      throw new Error("Authentication failed");
    }

    // Handle MFA if required
    let finalTx = await this.handleMfaIfRequired(tx, baseHeaders);

    // Get user ID
    const userId = finalTx?._embedded?.user?.id || tx?._embedded?.user?.id;
    if (!userId) {
      throw new Error("Unable to resolve user after authentication");
    }

    // Get user groups from Okta
    const userGroups = await this.getUserGroups(userId);

    return {
      type: "basic",
      source: "okta",
      username: credentials.name,
      userId: userId,
      groups: userGroups,
    };
  }

  /**
   * Handle MFA authentication if required
   * @param {Object} tx - Initial transaction response
   * @param {Object} baseHeaders - HTTP headers
   * @returns {Object} Final transaction response
   */
  async handleMfaIfRequired(tx, baseHeaders) {
    if (tx.status === "SUCCESS") {
      return tx; // No MFA required
    }

    if (tx.status === "MFA_REQUIRED" || tx.status === "MFA_CHALLENGE") {
      return await this.handleMfaChallenge(tx, baseHeaders);
    }

    throw new Error(`AuthN failed: ${tx.status || "UNKNOWN"}`);
  }

  /**
   * Handle MFA challenge (Okta Verify Push)
   * @param {Object} tx - Transaction response
   * @param {Object} baseHeaders - HTTP headers
   * @returns {Object} Final transaction response
   */
  async handleMfaChallenge(tx, baseHeaders) {
    const stateToken = tx.stateToken;
    const factors = tx._embedded?.factors || [];

    // Find Okta Verify Push factor
    const push = factors.find(
      (f) =>
        f.factorType === "push" &&
        f.provider &&
        (f.provider === "OKTA" || f.provider === "OKTA_VERIFY")
    );

    if (!push || !push._links?.verify?.href) {
      throw new Error(
        "MFA required but no Push factor available. Enroll Okta Verify Push or disable MFA."
      );
    }

    return await this.pollPushNotification(
      push._links.verify.href,
      stateToken,
      baseHeaders
    );
  }

  /**
   * Poll Okta Verify Push notification until approved
   * @param {string} verifyHref - Verify URL
   * @param {string} stateToken - State token
   * @param {Object} baseHeaders - HTTP headers
   * @returns {Object} Final transaction response
   */
  async pollPushNotification(
    verifyHref,
    stateToken,
    baseHeaders,
    timeoutMs = 90000,
    intervalMs = 3000
  ) {
    const verifyUrl = oktaConfig.resolveOktaUrl(verifyHref);
    if (!verifyUrl) {
      throw new Error("Invalid verify URL");
    }

    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const start = Date.now();
    let last;

    while (Date.now() - start < timeoutMs) {
      const resp = await axios.post(verifyUrl, { stateToken }, baseHeaders);
      last = resp.data;

      const factorResult = last.factorResult;
      const status = last.status;

      if (status === "SUCCESS" || factorResult === "SUCCESS") {
        return last;
      }

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
  }

  /**
   * Get user groups from Okta Management API
   * @param {string} userId - Okta user ID
   * @returns {Array} Array of group names
   */
  async getUserGroups(userId) {
    if (!oktaConfig.apiToken) {
      throw new Error("OKTA_API_TOKEN required for group lookup");
    }

    const groupsResponse = await axios.get(
      `${oktaConfig.apiUrl}/users/${userId}/groups`,
      { headers: { Authorization: `SSWS ${oktaConfig.apiToken}` } }
    );

    return (groupsResponse.data || [])
      .map((g) => g.profile?.name)
      .filter(Boolean);
  }
}

module.exports = new BasicAuthenticator();
