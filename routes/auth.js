const express = require('express');
const { body, validationResult } = require('express-validator');
const passport = require('passport');
const config = require('../config/config');
const userService = require('../services/userService');
const tokenUtils = require('../utils/tokenUtils');
const cryptoUtils = require('../utils/cryptoUtils');
const emailService = require('../services/emailService');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const rateLimiter = require('../middleware/rateLimiter');
const { isAuthenticated, authenticateToken } = require('../middleware/authMiddleware');

const router = express.Router();

/**
 * @route POST /auth/register
 * @desc Register a new user
 * @access Public
 */
router.post('/register', 
  rateLimiter.register,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: config.security.passwordMinLength }).withMessage(`Password must be at least ${config.security.passwordMinLength} characters long`),
    body('firstName').optional().trim().isLength({ min: 1, max: 50 }).withMessage('First name must be 1-50 characters'),
    body('lastName').optional().trim().isLength({ min: 1, max: 50 }).withMessage('Last name must be 1-50 characters')
  ],
  async (req, res) => {
    try {
      // Check if registration is enabled
      if (!config.features.enableRegistration) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Registration is currently disabled'
        });
      }

      // Validate input
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: errors.array()
        });
      }

      const { email, password, firstName, lastName } = req.body;

      // Create user
      const user = await userService.createUser({
        email,
        password,
        profile: {
          firstName,
          lastName,
          displayName: `${firstName} ${lastName}`.trim() || email
        }
      });

      // Log registration
      await auditService.log('user_registered', {
        userId: user._id,
        email: user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.status(201).json({
        message: 'User registered successfully',
        user: {
          id: user._id,
          email: user.email,
          status: user.status,
          emailVerified: user.emailVerified
        },
        requiresEmailVerification: config.security.requireEmailVerification
      });
    } catch (error) {
      logger.error('Registration error:', error);
      
      if (error.message.includes('already exists')) {
        return res.status(409).json({
          error: 'Conflict',
          message: 'User already exists with this email'
        });
      }

      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Registration failed'
      });
    }
  }
);

/**
 * @route POST /auth/login
 * @desc Login with email and password
 * @access Public
 */
router.post('/login',
  rateLimiter.login,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  async (req, res, next) => {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: errors.array()
      });
    }

    passport.authenticate('local', (err, user, info) => {
      if (err) {
        logger.error('Login authentication error:', err);
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Authentication failed'
        });
      }

      if (!user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: info.message || 'Authentication failed',
          requiresEmailVerification: info.requiresEmailVerification,
          requiresTwoFactor: info.requiresTwoFactor,
          userId: info.userId,
          accountLocked: info.accountLocked,
          accountInactive: info.accountInactive
        });
      }

      // Generate tokens
      const tokens = tokenUtils.generateTokenPair(user);

      // Set session if using sessions
      if (req.session) {
        req.session.userId = user._id;
        req.session.email = user.email;
      }

      res.json({
        message: 'Login successful',
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          profile: user.profile,
          roles: user.roles.map(r => r.name || r),
          status: user.status,
          emailVerified: user.emailVerified,
          twoFactorEnabled: user.twoFactorAuth?.enabled || false
        },
        tokens
      });
    })(req, res, next);
  }
);

/**
 * @route POST /auth/logout
 * @desc Logout user
 * @access Private
 */
router.post('/logout', isAuthenticated, async (req, res) => {
  try {
    // Blacklist JWT token if present
    if (req.token) {
      tokenUtils.blacklistToken(req.token);
    }

    // Destroy session
    if (req.session) {
      req.session.destroy((err) => {
        if (err) {
          logger.error('Session destruction error:', err);
        }
      });
    }

    // Remove session from user
    if (req.session?.id) {
      await req.user.removeSession(req.session.id);
    }

    // Log logout
    await auditService.log('user_logout', {
      userId: req.user._id,
      email: req.user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      message: 'Logout successful'
    });
  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Logout failed'
    });
  }
});

/**
 * @route POST /auth/refresh
 * @desc Refresh access token
 * @access Public
 */
router.post('/refresh',
  [
    body('refreshToken').notEmpty().withMessage('Refresh token is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Refresh token is required'
        });
      }

      const { refreshToken } = req.body;

      // Verify refresh token
      const decoded = tokenUtils.verifyRefreshToken(refreshToken);
      
      // Get user
      const user = await userService.getUserById(decoded.sub);
      if (!user || user.status !== 'active') {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid refresh token'
        });
      }

      // Generate new access token
      const accessToken = tokenUtils.generateAccessToken(user);

      // Log token refresh
      await auditService.log('token_refreshed', {
        userId: user._id,
        email: user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        accessToken,
        tokenType: 'Bearer',
        expiresIn: tokenUtils.getTokenExpirySeconds(config.jwt.expiresIn)
      });
    } catch (error) {
      logger.error('Token refresh error:', error);
      res.status(401).json({
        error: 'Unauthorized',
        message: error.message || 'Invalid refresh token'
      });
    }
  }
);

/**
 * @route GET /auth/me
 * @desc Get current user profile
 * @access Private
 */
router.get('/me', isAuthenticated, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        username: req.user.username,
        profile: req.user.profile,
        roles: req.user.roles.map(r => r.name || r),
        permissions: req.user.permissions,
        status: req.user.status,
        emailVerified: req.user.emailVerified,
        twoFactorEnabled: req.user.twoFactorAuth?.enabled || false,
        lastLogin: req.user.lastLogin,
        createdAt: req.user.createdAt,
        authMethod: req.user.authMethod
      }
    });
  } catch (error) {
    logger.error('Get profile error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get user profile'
    });
  }
});

/**
 * @route POST /auth/verify-email
 * @desc Verify email address
 * @access Public
 */
router.post('/verify-email',
  [
    body('token').notEmpty().withMessage('Verification token is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Verification token is required'
        });
      }

      const { token } = req.body;

      // Verify email
      const user = await userService.verifyEmail(token);

      res.json({
        message: 'Email verified successfully',
        user: {
          id: user._id,
          email: user.email,
          emailVerified: user.emailVerified,
          status: user.status
        }
      });
    } catch (error) {
      logger.error('Email verification error:', error);
      res.status(400).json({
        error: 'Bad Request',
        message: error.message || 'Email verification failed'
      });
    }
  }
);

/**
 * @route POST /auth/resend-verification
 * @desc Resend email verification
 * @access Private
 */
router.post('/resend-verification', 
  rateLimiter.emailVerification,
  isAuthenticated, 
  async (req, res) => {
    try {
      if (req.user.emailVerified) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Email is already verified'
        });
      }

      // Generate new verification token
      const token = req.user.generateEmailVerificationToken();
      await req.user.save();

      // Send verification email
      await emailService.sendVerificationEmail(req.user);

      res.json({
        message: 'Verification email sent successfully'
      });
    } catch (error) {
      logger.error('Resend verification error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to send verification email'
      });
    }
  }
);

/**
 * @route POST /auth/forgot-password
 * @desc Request password reset
 * @access Public
 */
router.post('/forgot-password',
  rateLimiter.passwordReset,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Valid email is required'
        });
      }

      const { email } = req.body;

      // Request password reset
      const result = await userService.requestPasswordReset(email);

      res.json(result);
    } catch (error) {
      logger.error('Forgot password error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Password reset request failed'
      });
    }
  }
);

/**
 * @route POST /auth/reset-password
 * @desc Reset password with token
 * @access Public
 */
router.post('/reset-password',
  [
    body('token').notEmpty().withMessage('Reset token is required'),
    body('password').isLength({ min: config.security.passwordMinLength }).withMessage(`Password must be at least ${config.security.passwordMinLength} characters long`)
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: errors.array()
        });
      }

      const { token, password } = req.body;

      // Reset password
      const user = await userService.resetPassword(token, password);

      res.json({
        message: 'Password reset successfully',
        user: {
          id: user._id,
          email: user.email
        }
      });
    } catch (error) {
      logger.error('Reset password error:', error);
      res.status(400).json({
        error: 'Bad Request',
        message: error.message || 'Password reset failed'
      });
    }
  }
);

/**
 * @route GET /auth/google
 * @desc Initiate Google OAuth
 * @access Public
 */
router.get('/google', 
  passport.authenticate('google', { 
    scope: ['profile', 'email'] 
  })
);

/**
 * @route GET /auth/google/callback
 * @desc Google OAuth callback
 * @access Public
 */
router.get('/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/auth/login?error=oauth_failed',
    session: true
  }),
  async (req, res) => {
    try {
      // Generate tokens for API access
      const tokens = tokenUtils.generateTokenPair(req.user);

      // Redirect with tokens (in production, use secure methods)
      const redirectUrl = new URL(process.env.FRONTEND_URL || 'http://localhost:3000/auth/callback');
      redirectUrl.searchParams.set('token', tokens.accessToken);
      redirectUrl.searchParams.set('refresh', tokens.refreshToken);

      res.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error('Google OAuth callback error:', error);
      res.redirect('/auth/login?error=oauth_callback_failed');
    }
  }
);

/**
 * @route GET /auth/github
 * @desc Initiate GitHub OAuth
 * @access Public
 */
router.get('/github', 
  passport.authenticate('github', { 
    scope: ['user:email'] 
  })
);

/**
 * @route GET /auth/github/callback
 * @desc GitHub OAuth callback
 * @access Public
 */
router.get('/github/callback',
  passport.authenticate('github', { 
    failureRedirect: '/auth/login?error=oauth_failed',
    session: true
  }),
  async (req, res) => {
    try {
      // Generate tokens for API access
      const tokens = tokenUtils.generateTokenPair(req.user);

      // Redirect with tokens
      const redirectUrl = new URL(process.env.FRONTEND_URL || 'http://localhost:3000/auth/callback');
      redirectUrl.searchParams.set('token', tokens.accessToken);
      redirectUrl.searchParams.set('refresh', tokens.refreshToken);

      res.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error('GitHub OAuth callback error:', error);
      res.redirect('/auth/login?error=oauth_callback_failed');
    }
  }
);

/**
 * @route POST /auth/saml
 * @desc Initiate SAML SSO
 * @access Public
 */
router.post('/saml',
  passport.authenticate('saml', { 
    failureRedirect: '/auth/login?error=saml_failed' 
  })
);

/**
 * @route POST /auth/saml/callback
 * @desc SAML SSO callback
 * @access Public
 */
router.post('/saml/callback',
  passport.authenticate('saml', { 
    failureRedirect: '/auth/login?error=saml_failed',
    session: true
  }),
  async (req, res) => {
    try {
      // Generate tokens for API access
      const tokens = tokenUtils.generateTokenPair(req.user);

      res.json({
        message: 'SAML authentication successful',
        user: {
          id: req.user._id,
          email: req.user.email,
          profile: req.user.profile,
          roles: req.user.roles.map(r => r.name || r)
        },
        tokens
      });
    } catch (error) {
      logger.error('SAML callback error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'SAML authentication failed'
      });
    }
  }
);

/**
 * @route POST /auth/ldap
 * @desc LDAP authentication
 * @access Public
 */
router.post('/ldap',
  rateLimiter.login,
  [
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Username and password are required'
      });
    }

    passport.authenticate('ldap', (err, user, info) => {
      if (err) {
        logger.error('LDAP authentication error:', err);
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'LDAP authentication failed'
        });
      }

      if (!user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: info.message || 'LDAP authentication failed'
        });
      }

      // Generate tokens
      const tokens = tokenUtils.generateTokenPair(user);

      res.json({
        message: 'LDAP authentication successful',
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          profile: user.profile,
          roles: user.roles.map(r => r.name || r)
        },
        tokens
      });
    })(req, res, next);
  }
);

/**
 * @route GET /auth/strategies
 * @desc Get available authentication strategies
 * @access Public
 */
router.get('/strategies', (req, res) => {
  try {
    const { getAuthStatus } = require('../auth/passport');
    const status = getAuthStatus();

    res.json({
      strategies: status.strategies,
      enabled: Object.values(status.strategies).filter(s => s.enabled),
      total: status.totalStrategies,
      enabledCount: status.enabledStrategies
    });
  } catch (error) {
    logger.error('Get strategies error:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to get authentication strategies'
    });
  }
});

// Mount additional authentication strategy routes
router.use('/magic-link', require('../auth/strategies/magicLinkStrategy'));
router.use('/2fa', require('../auth/strategies/totpStrategy'));

module.exports = router;
