require("dotenv").config();

/**
 * Okta Configuration Module
 * Centralizes all Okta-related configuration and URL building logic
 */

class OktaConfig {
  constructor() {
    this.orgUrl = this.getOrgBaseUrl();
    this.issuer = process.env.OKTA_ISSUER;
    this.clientId = process.env.OKTA_CLIENT_ID;
    this.audience = process.env.OKTA_AUDIENCE;
    this.apiToken = process.env.OKTA_API_TOKEN;

    // Build URLs
    const urls = this.buildOktaUrls();
    this.authnUrl = urls.authn;
    this.apiUrl = urls.api;
  }

  getOrgBaseUrl() {
    const explicit = process.env.OKTA_ORG_URL;
    if (explicit) return explicit.replace(/\/$/, "");

    const issuer = process.env.OKTA_ISSUER;
    if (!issuer) return undefined;

    try {
      const url = new URL(issuer);
      return `${url.protocol}//${url.host}`;
    } catch (_) {
      return undefined;
    }
  }

  buildOktaUrls() {
    const orgBase = this.orgUrl;
    const authn =
      process.env.OKTA_AUTHN_URL ||
      (orgBase ? `${orgBase}/api/v1/authn` : undefined);
    const api =
      process.env.OKTA_API_URL || (orgBase ? `${orgBase}/api/v1` : undefined);
    return { orgBase, authn, api };
  }

  resolveOktaUrl(href, orgBase = this.orgUrl) {
    if (!href) return undefined;
    if (/^https?:\/\//i.test(href)) return href;
    if (!orgBase) return undefined;
    if (href.startsWith("/")) return `${orgBase}${href}`;
    return `${orgBase}/${href}`;
  }

  validate() {
    const missing = [];
    const warnings = [];

    if (!this.issuer) missing.push("OKTA_ISSUER");
    if (!this.clientId) missing.push("OKTA_CLIENT_ID");
    if (!this.audience) missing.push("OKTA_AUDIENCE");
    if (!this.apiToken) warnings.push("OKTA_API_TOKEN");
    if (!this.authnUrl) missing.push("OKTA_AUTHN_URL or valid OKTA_ISSUER");

    return {
      isValid: missing.length === 0,
      missing,
      warnings,
      config: {
        orgUrl: this.orgUrl,
        issuer: this.issuer,
        clientId: this.clientId ? "SET" : "NOT SET",
        audience: this.audience,
        apiToken: this.apiToken ? "SET" : "NOT SET",
        authnUrl: this.authnUrl,
        apiUrl: this.apiUrl,
      },
    };
  }
}

module.exports = new OktaConfig();
