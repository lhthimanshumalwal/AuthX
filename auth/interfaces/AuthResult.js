/**
 * Standardized authentication result interface
 * This ensures consistent response format across all authentication strategies
 */
class AuthResult {
  constructor(data = {}) {
    this.success = data.success || false;
    this.user = data.user || null;
    this.tokens = data.tokens || null;
    this.strategy = data.strategy || null;
    this.timestamp = data.timestamp || new Date();
    this.metadata = data.metadata || {};
    this.error = data.error || null;
    this.redirectUrl = data.redirectUrl || null;
    this.requiresMFA = data.requiresMFA || false;
    this.mfaToken = data.mfaToken || null;
  }

  /**
   * Create a successful authentication result
   * @param {Object} user - Authenticated user object
   * @param {Object} options - Additional options
   * @returns {AuthResult} Success result
   */
  static success(user, options = {}) {
    return new AuthResult({
      success: true,
      user,
      tokens: options.tokens,
      strategy: options.strategy,
      metadata: options.metadata,
      redirectUrl: options.redirectUrl
    });
  }

  /**
   * Create a failed authentication result
   * @param {string|Error} error - Error message or Error object
   * @param {Object} options - Additional options
   * @returns {AuthResult} Failure result
   */
  static failure(error, options = {}) {
    const errorMessage = error instanceof Error ? error.message : error;
    return new AuthResult({
      success: false,
      error: errorMessage,
      strategy: options.strategy,
      metadata: options.metadata
    });
  }

  /**
   * Create a result that requires MFA
   * @param {string} mfaToken - MFA token for verification
   * @param {Object} options - Additional options
   * @returns {AuthResult} MFA required result
   */
  static requiresMFA(mfaToken, options = {}) {
    return new AuthResult({
      success: false,
      requiresMFA: true,
      mfaToken,
      strategy: options.strategy,
      metadata: options.metadata
    });
  }

  /**
   * Create a result that requires redirect (OAuth, SAML)
   * @param {string} redirectUrl - URL to redirect to
   * @param {Object} options - Additional options
   * @returns {AuthResult} Redirect result
   */
  static redirect(redirectUrl, options = {}) {
    return new AuthResult({
      success: false,
      redirectUrl,
      strategy: options.strategy,
      metadata: options.metadata
    });
  }

  /**
   * Check if authentication was successful
   * @returns {boolean} True if successful
   */
  isSuccess() {
    return this.success === true;
  }

  /**
   * Check if authentication failed
   * @returns {boolean} True if failed
   */
  isFailure() {
    return this.success === false && !this.requiresMFA && !this.redirectUrl;
  }

  /**
   * Check if MFA is required
   * @returns {boolean} True if MFA is required
   */
  isMFARequired() {
    return this.requiresMFA === true;
  }

  /**
   * Check if redirect is required
   * @returns {boolean} True if redirect is required
   */
  isRedirectRequired() {
    return !!this.redirectUrl;
  }

  /**
   * Get user information
   * @returns {Object|null} User object or null
   */
  getUser() {
    return this.user;
  }

  /**
   * Get authentication tokens
   * @returns {Object|null} Tokens object or null
   */
  getTokens() {
    return this.tokens;
  }

  /**
   * Get error message
   * @returns {string|null} Error message or null
   */
  getError() {
    return this.error;
  }

  /**
   * Get redirect URL
   * @returns {string|null} Redirect URL or null
   */
  getRedirectUrl() {
    return this.redirectUrl;
  }

  /**
   * Get MFA token
   * @returns {string|null} MFA token or null
   */
  getMFAToken() {
    return this.mfaToken;
  }

  /**
   * Get strategy name
   * @returns {string|null} Strategy name or null
   */
  getStrategy() {
    return this.strategy;
  }

  /**
   * Get metadata
   * @returns {Object} Metadata object
   */
  getMetadata() {
    return this.metadata;
  }

  /**
   * Add metadata
   * @param {string} key - Metadata key
   * @param {*} value - Metadata value
   */
  addMetadata(key, value) {
    this.metadata[key] = value;
  }

  /**
   * Convert to JSON representation
   * @returns {Object} JSON object
   */
  toJSON() {
    return {
      success: this.success,
      user: this.user,
      tokens: this.tokens,
      strategy: this.strategy,
      timestamp: this.timestamp,
      metadata: this.metadata,
      error: this.error,
      redirectUrl: this.redirectUrl,
      requiresMFA: this.requiresMFA,
      mfaToken: this.mfaToken
    };
  }

  /**
   * Convert to HTTP response format
   * @returns {Object} HTTP response object
   */
  toResponse() {
    const response = {
      success: this.success,
      timestamp: this.timestamp
    };

    if (this.success) {
      response.user = this.user;
      if (this.tokens) {
        response.tokens = this.tokens;
      }
    } else if (this.requiresMFA) {
      response.requiresMFA = true;
      response.mfaToken = this.mfaToken;
    } else if (this.redirectUrl) {
      response.redirectUrl = this.redirectUrl;
    } else {
      response.error = this.error;
    }

    return response;
  }

  /**
   * Get HTTP status code for this result
   * @returns {number} HTTP status code
   */
  getStatusCode() {
    if (this.success) {
      return 200;
    } else if (this.requiresMFA) {
      return 202; // Accepted, but requires additional action
    } else if (this.redirectUrl) {
      return 302; // Found, redirect required
    } else {
      return 401; // Unauthorized
    }
  }
}

module.exports = AuthResult;

