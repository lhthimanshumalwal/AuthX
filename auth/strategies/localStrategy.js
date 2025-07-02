const passport = require('passport');
const { Strategy: LocalStrategy } = require('passport-local');
const AuthStrategy = require('../interfaces/AuthStrategy');
const userService = require('../../services/userService');
const tokenUtils = require('../../utils/tokenUtils');
const { logger, audit } = require('../../utils/logger');

/**
 * Local Authentication Strategy
 * Handles email/password authentication
 */
class LocalAuthStrategy extends AuthStrategy {
  constructor(options = {}) {
    super('local', {
      enabled: true,
      priority: 80, // High priority for basic authentication
      ...options
    });
  }

  /**
   * Initialize the local strategy
   */
  async initialize() {
    try {
      const strategyOptions = {
        usernameField: 'email', // Use email as username field
        passwordField: 'password',
        passReqToCallback: true
      };

      const strategy = new LocalStrategy(strategyOptions, this.verify.bind(this));
      passport.use('local', strategy);

      logger.info('Local authentication strategy initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize local strategy:', error);
      throw error;
    }
  }

  /**
   * Validate strategy configuration
   */
  validateConfig() {
    // Local strategy doesn't require external configuration
    return true;
  }

  /**
   * Get strategy type
   */
  getType() {
    return 'local';
  }

  /**
   * Local strategy doesn't require redirect
   */
  requiresRedirect() {
    return false;
  }

  /**
   * Local strategy supports token refresh through JWT
   */
  supportsRefresh() {
    return true;
  }

  /**
   * Local strategy supports MFA
   */
  supportsMFA() {
    return true;
  }

  /**
   * Local strategy verification callback
   * @param {Object} req - Express request object
   * @param {string} email - User email
   * @param {string} password - User password
   * @param {Function} done - Passport done callback
   */
  async verify(req, email, password, done) {
    try {
      // Validate input
      if (!email || !password) {
        return done(null, false, { message: 'Email and password are required' });
      }

      // Authenticate user
      const authResult = await userService.authenticate(email, password, {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      if (!authResult.success) {
        return done(null, false, { message: authResult.error });
      }

      const user = authResult.user;

      // Check if MFA is enabled
      if (user.mfa.enabled) {
        // Generate MFA token
        const mfaToken = tokenUtils.generateMagicLinkToken({
          userId: user._id,
          email: user.email,
          purpose: 'mfa'
        });

        return done(null, false, {
          message: 'MFA verification required',
          requiresMFA: true,
          mfaToken: mfaToken,
          userId: user._id
        });
      }

      // Add strategy information
      user.strategy = 'local';

      return done(null, user);
    } catch (error) {
      logger.error('Local authentication error:', error);
      return done(error, false);
    }
  }

  /**
   * Handle successful authentication
   */
  async handleSuccess(user, tokens = null, req = null) {
    try {
      // Generate JWT tokens for local authentication
      const userPermissions = await userService.getPermissions(user._id);
      
      const tokenPair = tokenUtils.generateTokenPair({
        userId: user._id,
        email: user.email,
        roles: user.roles.map(role => role.name || role),
        permissions: userPermissions
      });

      const result = await super.handleSuccess(user, tokenPair, req);
      
      // Add local strategy specific metadata
      result.metadata.authMethod = 'password';
      result.metadata.mfaRequired = user.mfa.enabled;
      
      // Log successful authentication
      audit.authSuccess({
        userId: user._id,
        email: user.email,
        strategy: 'local',
        ip: req ? req.ip : null,
        userAgent: req ? req.get('User-Agent') : null
      });

      return result;
    } catch (error) {
      logger.error('Local authentication success handling error:', error);
      throw error;
    }
  }

  /**
   * Handle authentication failure
   */
  async handleFailure(error, req = null) {
    const result = await super.handleFailure(error, req);
    
    // Log failed authentication
    audit.authFailure({
      strategy: 'local',
      reason: error.message,
      ip: req ? req.ip : null,
      userAgent: req ? req.get('User-Agent') : null
    });

    return result;
  }

  /**
   * Pre-authentication hook
   */
  async preAuth(req) {
    try {
      // Validate request body
      if (!req.body.email || !req.body.password) {
        throw new Error('Email and password are required');
      }

      // Basic email format validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(req.body.email)) {
        throw new Error('Invalid email format');
      }

      // Password length validation
      if (req.body.password.length < 6) {
        throw new Error('Password must be at least 6 characters long');
      }

      return true;
    } catch (error) {
      logger.warn('Local authentication pre-auth validation failed:', error);
      return false;
    }
  }

  /**
   * Post-authentication hook
   */
  async postAuth(user, req) {
    try {
      // Update last login information
      if (user && user._id) {
        await userService.update(user._id, {
          'security.lastLogin': new Date(),
          'security.lastLoginIP': req ? req.ip : null
        });
      }
    } catch (error) {
      logger.error('Local authentication post-auth hook error:', error);
      // Don't throw error as authentication was successful
    }
  }

  /**
   * Get authentication routes for local strategy
   */
  getRoutes() {
    return [
      {
        method: 'POST',
        path: '/auth/login',
        handler: 'login',
        description: 'Login with email and password'
      },
      {
        method: 'POST',
        path: '/auth/register',
        handler: 'register',
        description: 'Register new user account'
      },
      {
        method: 'POST',
        path: '/auth/forgot-password',
        handler: 'forgotPassword',
        description: 'Request password reset'
      },
      {
        method: 'POST',
        path: '/auth/reset-password',
        handler: 'resetPassword',
        description: 'Reset password with token'
      },
      {
        method: 'POST',
        path: '/auth/change-password',
        handler: 'changePassword',
        description: 'Change password for authenticated user'
      }
    ];
  }

  /**
   * Get middleware for local strategy
   */
  getMiddleware() {
    return [
      {
        name: 'localAuth',
        middleware: passport.authenticate('local', { session: false }),
        description: 'Local authentication middleware'
      }
    ];
  }

  /**
   * Login handler
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async login(req, res) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: 'Email and password are required'
        });
      }

      // Authenticate user
      const authResult = await userService.authenticate(email, password, {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      if (!authResult.success) {
        return res.status(401).json({
          success: false,
          error: authResult.error
        });
      }

      const user = authResult.user;

      // Check if MFA is enabled
      if (user.mfa.enabled) {
        const mfaToken = tokenUtils.generateMagicLinkToken({
          userId: user._id,
          email: user.email,
          purpose: 'mfa'
        });

        return res.status(202).json({
          success: false,
          requiresMFA: true,
          mfaToken: mfaToken,
          message: 'MFA verification required'
        });
      }

      // Generate tokens
      const userPermissions = await userService.getPermissions(user._id);
      const tokenPair = tokenUtils.generateTokenPair({
        userId: user._id,
        email: user.email,
        roles: user.roles.map(role => role.name || role),
        permissions: userPermissions
      });

      // Update last login
      await this.postAuth(user, req);

      res.json({
        success: true,
        user: {
          id: user._id,
          email: user.email,
          profile: user.profile,
          roles: user.roles,
          emailVerified: user.emailVerified,
          status: user.status
        },
        tokens: tokenPair
      });
    } catch (error) {
      logger.error('Login error:', error);
      res.status(500).json({
        success: false,
        error: 'Login failed'
      });
    }
  }

  /**
   * Register handler
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async register(req, res) {
    try {
      const { email, password, firstName, lastName } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: 'Email and password are required'
        });
      }

      // Create user
      const user = await userService.create({
        email,
        password,
        profile: {
          firstName,
          lastName,
          displayName: firstName && lastName ? `${firstName} ${lastName}` : email
        }
      }, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        source: 'registration'
      });

      res.status(201).json({
        success: true,
        user: {
          id: user._id,
          email: user.email,
          profile: user.profile,
          status: user.status,
          emailVerified: user.emailVerified
        },
        message: user.emailVerified ? 'Account created successfully' : 'Account created. Please verify your email.'
      });
    } catch (error) {
      logger.error('Registration error:', error);
      res.status(400).json({
        success: false,
        error: error.message || 'Registration failed'
      });
    }
  }

  /**
   * Forgot password handler
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async forgotPassword(req, res) {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          error: 'Email is required'
        });
      }

      const user = await userService.findByEmail(email);
      if (!user) {
        // Don't reveal if email exists
        return res.json({
          success: true,
          message: 'If the email exists, a password reset link has been sent'
        });
      }

      // Generate reset token
      const resetToken = tokenUtils.generateSecureToken();
      await userService.update(user._id, {
        passwordResetToken: resetToken,
        passwordResetExpires: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
      });

      // TODO: Send email with reset link
      logger.info('Password reset requested', {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });

      res.json({
        success: true,
        message: 'Password reset link has been sent to your email'
      });
    } catch (error) {
      logger.error('Forgot password error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to process password reset request'
      });
    }
  }

  /**
   * Reset password handler
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async resetPassword(req, res) {
    try {
      const { token, password } = req.body;

      if (!token || !password) {
        return res.status(400).json({
          success: false,
          error: 'Token and new password are required'
        });
      }

      const success = await userService.resetPassword(token, password);
      if (!success) {
        return res.status(400).json({
          success: false,
          error: 'Invalid or expired reset token'
        });
      }

      res.json({
        success: true,
        message: 'Password reset successfully'
      });
    } catch (error) {
      logger.error('Reset password error:', error);
      res.status(400).json({
        success: false,
        error: error.message || 'Password reset failed'
      });
    }
  }

  /**
   * Change password handler
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async changePassword(req, res) {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user ? req.user.id : null;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          success: false,
          error: 'Current password and new password are required'
        });
      }

      const success = await userService.changePassword(userId, currentPassword, newPassword, {
        changedBy: userId,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      if (!success) {
        return res.status(400).json({
          success: false,
          error: 'Failed to change password'
        });
      }

      res.json({
        success: true,
        message: 'Password changed successfully'
      });
    } catch (error) {
      logger.error('Change password error:', error);
      res.status(400).json({
        success: false,
        error: error.message || 'Password change failed'
      });
    }
  }
}

module.exports = LocalAuthStrategy;

