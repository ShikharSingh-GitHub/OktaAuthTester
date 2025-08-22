const basicAuth = require("./basicAuth");
const jwtAuth = require("./jwtAuth");

/**
 * Authentication Orchestrator
 * Routes authentication requests to appropriate handlers
 */

class AuthenticationService {
  /**
   * Authenticate incoming request based on Authorization header
   * @param {Object} req - Express request object
   * @returns {Object} User object with authentication details
   */
  async authenticate(req) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      throw new Error("Missing authorization header");
    }

    // Route to appropriate authenticator
    if (authHeader.startsWith("Basic ")) {
      return await basicAuth.authenticate(authHeader);
    } else if (authHeader.startsWith("Bearer ")) {
      return await jwtAuth.authenticate(authHeader);
    } else {
      throw new Error("Unsupported authorization type. Use Basic or Bearer.");
    }
  }

  /**
   * Express middleware for authentication
   * @param {Object} req - Express request
   * @param {Object} res - Express response
   * @param {Function} next - Next middleware function
   */
  middleware() {
    return async (req, res, next) => {
      try {
        const user = await this.authenticate(req);
        req.user = user;
        next();
      } catch (error) {
        console.error("Authentication failed:", error.message);

        // Determine appropriate error response
        const statusCode = this.getErrorStatusCode(error.message);
        res.status(statusCode).json({
          error: "Authentication failed",
          details: error.message,
        });
      }
    };
  }

  /**
   * Determine HTTP status code based on error message
   * @param {string} errorMessage - Error message
   * @returns {number} HTTP status code
   */
  getErrorStatusCode(errorMessage) {
    if (errorMessage.includes("Missing authorization")) return 401;
    if (errorMessage.includes("Invalid") || errorMessage.includes("expired"))
      return 401;
    if (errorMessage.includes("Unsupported")) return 401;
    if (
      errorMessage.includes("misconfiguration") ||
      errorMessage.includes("not configured")
    )
      return 500;
    return 401; // Default to 401 for authentication errors
  }
}

module.exports = new AuthenticationService();
