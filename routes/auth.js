const express = require('express');
const passport = require('passport');
const { asyncHandler } = require('../middleware/errorHandler');
const rateLimiting = require('../middleware/rateLimiting');
const { isAuthenticated, getCurrentUser } = require('../auth/passport');
const strategyRegistry = require('../auth/strategyRegistry');
const tokenUtils = require('../utils/tokenUtils');
const userService = require('../services/userService');
const { logger } = require('../utils/logger');

const router = express.Router();

/**
 * Authentication Routes
 * Provides endpoints for all authentication operations
 */

/**
 * GET /auth/methods
 * Get available authentication methods
 */
router.get('/methods', asyncHandler(async (req, res) => {
  const methods = strategyRegistry.getMetadata();
  res.json({
    success: true,
    methods
  });
}));

/**
 * POST /auth/login
 * Generic login endpoint that handles multiple strategies
 */
router.post('/login', 
  rateLimiting.login,
  asyncHandler(async (req, res) => {
    const { strategy = 'local', ...credentials } = req.body;
    
    // Get the requested strategy
    const authStrategy = strategyRegistry.get(strategy);
    if (!authStrategy) {
      return res.status(400).json({
        success: false,
        error: `Authentication strategy '${strategy}' not found`
      });
    }

    if (!authStrategy.enabled) {
      return res.status(400).json({
        success: false,
        error: `Authentication strategy '${strategy}' is disabled`
      });
    }

    // Handle strategy-specific login
    if (strategy === 'local') {
      const localStrategy = strategyRegistry.get('local');
      return await localStrategy.login(req, res);
    } else if (authStrategy.requiresRedirect()) {
      // For OAuth/SAML strategies that require redirect
      return res.json({
        success: false,
        redirectUrl: `/auth/${strategy}`,
        message: 'Redirect required for this authentication method'
      });
    } else {
      // Use Passport authentication
      passport.authenticate(strategy, { session: false }, async (err, user, info) => {
        if (err) {
          logger.error(`Authentication error for strategy '${strategy}':`, err);
          return res.status(500).json({
            success: false,
            error: 'Authentication failed'
          });
        }

        if (!user) {
          const error = info ? info.message : 'Authentication failed';
          return res.status(401).json({
            success: false,
            error
          });
        }

        try {
          const result = await authStrategy.handleSuccess(user, null, req);
          return res.status(result.getStatusCode()).json(result.toResponse());
        } catch (error) {
          logger.error('Post-authentication error:', error);
          return res.status(500).json({
            success: false,
            error: 'Authentication processing failed'
          });
        }
      })(req, res);
    }
  })
);

/**
 * POST /auth/logout
 * Logout endpoint
 */
router.post('/logout', asyncHandler(async (req, res) => {
  // If using sessions
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        logger.error('Session destruction error:', err);
      }
    });
  }

  // If using JWT, client should discard the token
  // In a production system, you might want to blacklist the token

  res.json({
    success: true,
    message: 'Logged out successfully'
  });
}));

/**
 * GET /auth/me
 * Get current user information
 */
router.get('/me', 
  passport.authenticate(['jwt', 'session'], { session: false }),
  asyncHandler(async (req, res) => {
    const user = getCurrentUser(req);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Not authenticated'
      });
    }

    // Get user permissions
    const permissions = await userService.getPermissions(user._id || user.id);

    res.json({
      success: true,
      user: {
        id: user._id || user.id,
        email: user.email,
        profile: user.profile,
        roles: user.roles,
        permissions,
        emailVerified: user.emailVerified,
        status: user.status,
        mfa: {
          enabled: user.mfa ? user.mfa.enabled : false,
          methods: user.mfa ? user.mfa.methods : []
        },
        lastLogin: user.security ? user.security.lastLogin : null
      }
    });
  })
);

/**
 * POST /auth/register
 * User registration endpoint
 */
router.post('/register',
  rateLimiting.registration,
  asyncHandler(async (req, res) => {
    const localStrategy = strategyRegistry.get('local');
    if (!localStrategy) {
      return res.status(400).json({
        success: false,
        error: 'Registration not available'
      });
    }

    return await localStrategy.register(req, res);
  })
);

/**
 * POST /auth/forgot-password
 * Forgot password endpoint
 */
router.post('/forgot-password',
  rateLimiting.passwordReset,
  asyncHandler(async (req, res) => {
    const localStrategy = strategyRegistry.get('local');
    if (!localStrategy) {
      return res.status(400).json({
        success: false,
        error: 'Password reset not available'
      });
    }

    return await localStrategy.forgotPassword(req, res);
  })
);

/**
 * POST /auth/reset-password
 * Reset password endpoint
 */
router.post('/reset-password',
  rateLimiting.passwordReset,
  asyncHandler(async (req, res) => {
    const localStrategy = strategyRegistry.get('local');
    if (!localStrategy) {
      return res.status(400).json({
        success: false,
        error: 'Password reset not available'
      });
    }

    return await localStrategy.resetPassword(req, res);
  })
);

/**
 * POST /auth/change-password
 * Change password endpoint (requires authentication)
 */
router.post('/change-password',
  passport.authenticate(['jwt', 'session'], { session: false }),
  asyncHandler(async (req, res) => {
    const localStrategy = strategyRegistry.get('local');
    if (!localStrategy) {
      return res.status(400).json({
        success: false,
        error: 'Password change not available'
      });
    }

    return await localStrategy.changePassword(req, res);
  })
);

/**
 * POST /auth/token/refresh
 * Refresh JWT token
 */
router.post('/token/refresh', asyncHandler(async (req, res) => {
  const jwtStrategy = strategyRegistry.get('jwt');
  if (!jwtStrategy) {
    return res.status(400).json({
      success: false,
      error: 'JWT authentication not available'
    });
  }

  return await jwtStrategy.refreshToken(req, res);
}));

/**
 * POST /auth/token/verify
 * Verify JWT token
 */
router.post('/token/verify', asyncHandler(async (req, res) => {
  const jwtStrategy = strategyRegistry.get('jwt');
  if (!jwtStrategy) {
    return res.status(400).json({
      success: false,
      error: 'JWT authentication not available'
    });
  }

  return await jwtStrategy.verifyToken(req, res);
}));

/**
 * POST /auth/token/revoke
 * Revoke JWT token
 */
router.post('/token/revoke',
  passport.authenticate('jwt', { session: false }),
  asyncHandler(async (req, res) => {
    const jwtStrategy = strategyRegistry.get('jwt');
    if (!jwtStrategy) {
      return res.status(400).json({
        success: false,
        error: 'JWT authentication not available'
      });
    }

    return await jwtStrategy.revokeToken(req, res);
  })
);

/**
 * GET /auth/verify-email/:token
 * Email verification endpoint
 */
router.get('/verify-email/:token', asyncHandler(async (req, res) => {
  try {
    const { token } = req.params;
    const success = await userService.verifyEmail(token);
    
    if (success) {
      res.json({
        success: true,
        message: 'Email verified successfully'
      });
    } else {
      res.status(400).json({
        success: false,
        error: 'Invalid or expired verification token'
      });
    }
  } catch (error) {
    logger.error('Email verification error:', error);
    res.status(400).json({
      success: false,
      error: error.message || 'Email verification failed'
    });
  }
}));

/**
 * GET /auth/protected
 * Protected route example
 */
router.get('/protected',
  passport.authenticate(['jwt', 'session'], { session: false }),
  asyncHandler(async (req, res) => {
    res.json({
      success: true,
      message: 'Access granted to protected resource',
      user: {
        id: req.user._id || req.user.id,
        email: req.user.email
      },
      timestamp: new Date().toISOString()
    });
  })
);

/**
 * Dynamic OAuth routes
 * These routes are generated based on available OAuth strategies
 */
const setupOAuthRoutes = () => {
  const oauthStrategies = strategyRegistry.getByType('oauth');
  
  oauthStrategies.forEach(strategy => {
    if (!strategy.enabled) return;

    const strategyName = strategy.name;
    
    // OAuth initiation route
    router.get(`/${strategyName}`,
      passport.authenticate(strategyName, { 
        scope: strategy.options.scope || ['profile', 'email'] 
      })
    );

    // OAuth callback route
    router.get(`/${strategyName}/callback`,
      passport.authenticate(strategyName, { session: false }),
      asyncHandler(async (req, res) => {
        try {
          if (!req.user) {
            return res.redirect('/login?error=oauth_failed');
          }

          const result = await strategy.handleSuccess(req.user, null, req);
          
          // For web applications, you might want to redirect with tokens
          // For APIs, return JSON response
          if (req.query.format === 'json') {
            return res.json(result.toResponse());
          }

          // Redirect to frontend with tokens (for web apps)
          const tokens = result.getTokens();
          const redirectUrl = `/dashboard?token=${tokens.accessToken}&refresh=${tokens.refreshToken}`;
          res.redirect(redirectUrl);
        } catch (error) {
          logger.error(`OAuth callback error for ${strategyName}:`, error);
          res.redirect('/login?error=oauth_error');
        }
      })
    );
  });
};

// Setup OAuth routes after strategies are initialized
setTimeout(setupOAuthRoutes, 1000);

module.exports = router;

