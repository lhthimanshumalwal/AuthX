const passport = require('passport');
const { asyncHandler } = require('./errorHandler');
const userService = require('../services/userService');
const tokenUtils = require('../utils/tokenUtils');
const { logger } = require('../utils/logger');

/**
 * Authentication Middleware Collection
 * Provides various authentication and authorization middleware functions
 */

/**
 * Check if user is authenticated
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const isAuthenticated = asyncHandler(async (req, res, next) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }

  // Check for JWT token
  const token = tokenUtils.extractTokenFromHeader(req.headers.authorization);
  if (token) {
    try {
      const decoded = tokenUtils.verifyAccessToken(token);
      const user = await userService.findById(decoded.sub);
      
      if (user && user.status === 'active') {
        req.user = user;
        return next();
      }
    } catch (error) {
      // Token is invalid, continue to unauthorized response
    }
  }

  return res.status(401).json({
    success: false,
    error: 'Authentication required',
    code: 'AUTHENTICATION_REQUIRED'
  });
});

/**
 * Check if user has specific role
 * @param {string|Array} roles - Required role(s)
 * @returns {Function} Middleware function
 */
const hasRole = (roles) => {
  const requiredRoles = Array.isArray(roles) ? roles : [roles];
  
  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTHENTICATION_REQUIRED'
      });
    }

    const user = await userService.findById(req.user._id || req.user.id);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const userRoles = user.roles.map(role => role.name || role);
    const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));

    if (!hasRequiredRole) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Required role(s): ${requiredRoles.join(', ')}`,
        code: 'INSUFFICIENT_ROLE'
      });
    }

    next();
  });
};

/**
 * Check if user has specific permission
 * @param {string|Array} permissions - Required permission(s)
 * @returns {Function} Middleware function
 */
const hasPermission = (permissions) => {
  const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions];
  
  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTHENTICATION_REQUIRED'
      });
    }

    const userId = req.user._id || req.user.id;
    
    // Check each required permission
    for (const permission of requiredPermissions) {
      const hasAccess = await userService.hasPermission(userId, permission);
      if (!hasAccess) {
        return res.status(403).json({
          success: false,
          error: `Access denied. Required permission: ${permission}`,
          code: 'INSUFFICIENT_PERMISSION'
        });
      }
    }

    next();
  });
};

/**
 * Check if user can access resource (owns it or has admin permission)
 * @param {string} resourceIdParam - Parameter name containing resource ID
 * @param {string} userIdField - Field name in resource containing user ID
 * @returns {Function} Middleware function
 */
const canAccessResource = (resourceIdParam = 'id', userIdField = 'userId') => {
  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTHENTICATION_REQUIRED'
      });
    }

    const userId = req.user._id || req.user.id;
    const resourceId = req.params[resourceIdParam];

    // Check if user is admin
    const isAdmin = await userService.hasPermission(userId, 'admin:*');
    if (isAdmin) {
      return next();
    }

    // Check if user owns the resource
    if (resourceId === userId.toString()) {
      return next();
    }

    // For more complex ownership checks, you would query the resource
    // and check the userIdField
    
    return res.status(403).json({
      success: false,
      error: 'Access denied. You can only access your own resources.',
      code: 'RESOURCE_ACCESS_DENIED'
    });
  });
};

/**
 * Optional authentication middleware
 * Sets req.user if authenticated but doesn't require authentication
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const optionalAuth = asyncHandler(async (req, res, next) => {
  // Check for session authentication
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }

  // Check for JWT token
  const token = tokenUtils.extractTokenFromHeader(req.headers.authorization);
  if (token) {
    try {
      const decoded = tokenUtils.verifyAccessToken(token);
      const user = await userService.findById(decoded.sub);
      
      if (user && user.status === 'active') {
        req.user = user;
      }
    } catch (error) {
      // Token is invalid, but that's okay for optional auth
      logger.debug('Optional auth token verification failed:', error.message);
    }
  }

  next();
});

/**
 * Require email verification middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireEmailVerification = asyncHandler(async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      code: 'AUTHENTICATION_REQUIRED'
    });
  }

  const user = await userService.findById(req.user._id || req.user.id);
  if (!user) {
    return res.status(401).json({
      success: false,
      error: 'User not found',
      code: 'USER_NOT_FOUND'
    });
  }

  if (!user.emailVerified) {
    return res.status(403).json({
      success: false,
      error: 'Email verification required',
      code: 'EMAIL_VERIFICATION_REQUIRED'
    });
  }

  next();
});

/**
 * Require active account status middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireActiveAccount = asyncHandler(async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      code: 'AUTHENTICATION_REQUIRED'
    });
  }

  const user = await userService.findById(req.user._id || req.user.id);
  if (!user) {
    return res.status(401).json({
      success: false,
      error: 'User not found',
      code: 'USER_NOT_FOUND'
    });
  }

  if (user.status !== 'active') {
    return res.status(403).json({
      success: false,
      error: `Account is ${user.status}. Please contact support.`,
      code: 'ACCOUNT_NOT_ACTIVE'
    });
  }

  next();
});

/**
 * API key authentication middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const apiKeyAuth = asyncHandler(async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({
      success: false,
      error: 'API key required',
      code: 'API_KEY_REQUIRED'
    });
  }

  // TODO: Implement API key validation
  // This would typically involve:
  // 1. Looking up the API key in the database
  // 2. Checking if it's active and not expired
  // 3. Loading the associated user/application
  // 4. Setting req.user or req.apiKey

  return res.status(501).json({
    success: false,
    error: 'API key authentication not yet implemented',
    code: 'NOT_IMPLEMENTED'
  });
});

/**
 * Combine multiple authentication strategies
 * @param {Array} strategies - Array of strategy names
 * @returns {Function} Middleware function
 */
const multiAuth = (strategies = ['jwt', 'session']) => {
  return passport.authenticate(strategies, { session: false });
};

/**
 * Create custom authorization middleware
 * @param {Function} authorizationFunction - Custom authorization function
 * @returns {Function} Middleware function
 */
const customAuth = (authorizationFunction) => {
  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTHENTICATION_REQUIRED'
      });
    }

    const isAuthorized = await authorizationFunction(req.user, req);
    
    if (!isAuthorized) {
      return res.status(403).json({
        success: false,
        error: 'Access denied',
        code: 'CUSTOM_AUTHORIZATION_FAILED'
      });
    }

    next();
  });
};

module.exports = {
  isAuthenticated,
  hasRole,
  hasPermission,
  canAccessResource,
  optionalAuth,
  requireEmailVerification,
  requireActiveAccount,
  apiKeyAuth,
  multiAuth,
  customAuth
};

