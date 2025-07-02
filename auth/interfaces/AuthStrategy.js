/**
 * Base interface for all authentication strategies
 * This provides a unified contract that all authentication strategies must implement
 */
class AuthStrategy {
  constructor(name, options = {}) {
    if (this.constructor === AuthStrategy) {
      throw new Error('AuthStrategy is an abstract class and cannot be instantiated directly');
    }
    
    this.name = name;
    this.options = options;
    this.enabled = options.enabled !== false;
    this.priority = options.priority || 0;
  }

  /**
   * Initialize the strategy
   * This method should set up the Passport strategy and any required configuration
   * @abstract
   */
  async initialize() {
    throw new Error('initialize() method must be implemented by strategy');
  }

  /**
   * Validate strategy configuration
   * @abstract
   * @returns {boolean} True if configuration is valid
   */
  validateConfig() {
    throw new Error('validateConfig() method must be implemented by strategy');
  }

  /**
   * Get strategy metadata
   * @returns {Object} Strategy metadata
   */
  getMetadata() {
    return {
      name: this.name,
      enabled: this.enabled,
      priority: this.priority,
      type: this.getType(),
      requiresRedirect: this.requiresRedirect(),
      supportsRefresh: this.supportsRefresh(),
      supportsMFA: this.supportsMFA()
    };
  }

  /**
   * Get strategy type (jwt, oauth, saml, ldap, local, etc.)
   * @abstract
   * @returns {string} Strategy type
   */
  getType() {
    throw new Error('getType() method must be implemented by strategy');
  }

  /**
   * Check if strategy requires redirect (OAuth, SAML)
   * @returns {boolean} True if strategy requires redirect
   */
  requiresRedirect() {
    return false;
  }

  /**
   * Check if strategy supports token refresh
   * @returns {boolean} True if strategy supports refresh
   */
  supportsRefresh() {
    return false;
  }

  /**
   * Check if strategy supports MFA
   * @returns {boolean} True if strategy supports MFA
   */
  supportsMFA() {
    return false;
  }

  /**
   * Handle successful authentication
   * This method processes the authentication result and returns a standardized user object
   * @param {Object} profile - User profile from authentication provider
   * @param {Object} tokens - Authentication tokens (if any)
   * @param {Object} req - Express request object
   * @returns {Promise<AuthResult>} Standardized authentication result
   */
  async handleSuccess(profile, tokens = null, req = null) {
    // Default implementation - strategies can override this
    return {
      success: true,
      user: profile,
      tokens: tokens,
      strategy: this.name,
      timestamp: new Date(),
      metadata: {
        ip: req ? req.ip : null,
        userAgent: req ? req.get('User-Agent') : null
      }
    };
  }

  /**
   * Handle authentication failure
   * @param {Error} error - Authentication error
   * @param {Object} req - Express request object
   * @returns {Promise<AuthResult>} Standardized authentication result
   */
  async handleFailure(error, req = null) {
    return {
      success: false,
      error: error.message || 'Authentication failed',
      strategy: this.name,
      timestamp: new Date(),
      metadata: {
        ip: req ? req.ip : null,
        userAgent: req ? req.get('User-Agent') : null
      }
    };
  }

  /**
   * Pre-authentication hook
   * Called before authentication attempt
   * @param {Object} req - Express request object
   * @returns {Promise<boolean>} True to continue, false to abort
   */
  async preAuth(req) {
    return true;
  }

  /**
   * Post-authentication hook
   * Called after successful authentication
   * @param {Object} user - Authenticated user
   * @param {Object} req - Express request object
   * @returns {Promise<void>}
   */
  async postAuth(user, req) {
    // Default implementation - strategies can override
  }

  /**
   * Cleanup method
   * Called when strategy is being removed or server is shutting down
   * @returns {Promise<void>}
   */
  async cleanup() {
    // Default implementation - strategies can override
  }

  /**
   * Get authentication routes for this strategy
   * @returns {Array} Array of route definitions
   */
  getRoutes() {
    return [];
  }

  /**
   * Get middleware for this strategy
   * @returns {Array} Array of middleware functions
   */
  getMiddleware() {
    return [];
  }

  /**
   * Serialize user for session
   * @param {Object} user - User object
   * @returns {Promise<string>} Serialized user identifier
   */
  async serializeUser(user) {
    return user.id || user._id;
  }

  /**
   * Deserialize user from session
   * @param {string} id - User identifier
   * @returns {Promise<Object>} User object
   */
  async deserializeUser(id) {
    // Default implementation - strategies should override if needed
    const userService = require('../../services/userService');
    return await userService.findById(id);
  }
}

module.exports = AuthStrategy;

