const { Strategy: LocalStrategy } = require('passport-local');
const userService = require('../../services/userService');
const logger = require('../../utils/logger');
const auditService = require('../../services/auditService');

/**
 * Local Authentication Strategy
 * Used for email/password authentication
 */
const createLocalStrategy = () => {
  const options = {
    usernameField: 'email', // Use email as username field
    passwordField: 'password',
    passReqToCallback: true // Pass request to callback for additional context
  };

  return new LocalStrategy(options, async (req, email, password, done) => {
    try {
      // Get device information from request
      const deviceInfo = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        timestamp: new Date()
      };

      logger.debug('Local authentication attempt', {
        email: email,
        ip: deviceInfo.ip,
        userAgent: deviceInfo.userAgent
      });

      // Validate input
      if (!email || !password) {
        await auditService.log('login_failed', {
          email: email,
          reason: 'missing_credentials',
          deviceInfo
        });
        
        return done(null, false, { 
          message: 'Email and password are required' 
        });
      }

      // Normalize email
      email = email.toLowerCase().trim();

      // Authenticate user
      const user = await userService.authenticateUser(email, password, deviceInfo);
      
      if (!user) {
        // This shouldn't happen as authenticateUser throws on failure
        return done(null, false, { 
          message: 'Authentication failed' 
        });
      }

      // Check if email verification is required
      if (!user.emailVerified && process.env.REQUIRE_EMAIL_VERIFICATION === 'true') {
        logger.info('Login attempt with unverified email', {
          userId: user._id,
          email: user.email,
          ip: deviceInfo.ip
        });

        await auditService.log('login_failed', {
          userId: user._id,
          email: user.email,
          reason: 'email_not_verified',
          deviceInfo
        });

        return done(null, false, { 
          message: 'Please verify your email address before logging in',
          requiresEmailVerification: true,
          userId: user._id
        });
      }

      // Check if 2FA is enabled
      if (user.twoFactorAuth?.enabled) {
        logger.info('2FA required for user', {
          userId: user._id,
          email: user.email,
          ip: deviceInfo.ip
        });

        // Don't complete authentication yet - require 2FA
        return done(null, false, { 
          message: 'Two-factor authentication required',
          requiresTwoFactor: true,
          userId: user._id,
          email: user.email
        });
      }

      // Create session information
      const sessionInfo = {
        loginMethod: 'password',
        deviceInfo: deviceInfo,
        timestamp: new Date()
      };

      // Add session to user (if session tracking is enabled)
      if (req.session) {
        await user.addSession(req.session.id, deviceInfo);
      }

      // Log successful authentication
      await auditService.log('login_success', {
        userId: user._id,
        email: user.email,
        method: 'local',
        deviceInfo,
        sessionInfo
      });

      logger.info('Local authentication successful', {
        userId: user._id,
        email: user.email,
        ip: deviceInfo.ip
      });

      // Attach authentication metadata
      user.authMethod = 'local';
      user.authTimestamp = new Date();
      user.sessionInfo = sessionInfo;

      return done(null, user);
    } catch (error) {
      logger.error('Local strategy authentication error:', error);

      // Log authentication error
      await auditService.log('login_error', {
        email: email,
        error: error.message,
        deviceInfo: {
          ip: req.ip,
          userAgent: req.get('User-Agent')
        }
      });

      // Handle specific error types
      if (error.message === 'Invalid credentials') {
        return done(null, false, { 
          message: 'Invalid email or password' 
        });
      }

      if (error.message.includes('locked')) {
        return done(null, false, { 
          message: error.message,
          accountLocked: true 
        });
      }

      if (error.message.includes('not active')) {
        return done(null, false, { 
          message: 'Account is not active. Please contact support.',
          accountInactive: true 
        });
      }

      // Generic error for security
      return done(null, false, { 
        message: 'Authentication failed. Please try again.' 
      });
    }
  });
};

module.exports = createLocalStrategy;

