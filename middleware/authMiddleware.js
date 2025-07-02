const tokenUtils = require('../utils/tokenUtils');
const userService = require('../services/userService');
const logger = require('../utils/logger');
const auditService = require('../services/auditService');

/**
 * Middleware to authenticate JWT tokens
 */
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = tokenUtils.extractTokenFromHeader(authHeader);

    if (!token) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Access token is required'
      });
    }

    // Verify token
    const decoded = tokenUtils.verifyAccessToken(token);
    
    // Get user from database
    const user = await userService.getUserById(decoded.sub);
    if (!user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'User not found'
      });
    }

    // Check if user is active
    if (user.status !== 'active') {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'User account is not active'
      });
    }

    // Attach user to request
    req.user = user;
    req.token = token;
    req.tokenPayload = decoded;

    next();
  } catch (error) {
    logger.error('Token authentication error:', error);
    
    // Log failed authentication attempt
    await auditService.log('token_auth_failed', {
      error: error.message,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path
    });

    return res.status(401).json({
      error: 'Unauthorized',
      message: error.message || 'Invalid or expired token'
    });
  }
};

/**
 * Middleware to check if user is authenticated (either session or token)
 */
const isAuthenticated = async (req, res, next) => {
  try {
    // Check for JWT token first
    const authHeader = req.headers.authorization;
    const token = tokenUtils.extractTokenFromHeader(authHeader);

    if (token) {
      // Use JWT authentication
      return authenticateToken(req, res, next);
    }

    // Check for session authentication
    if (req.session && req.session.userId) {
      const user = await userService.getUserById(req.session.userId);
      if (user && user.status === 'active') {
        req.user = user;
        req.sessionAuth = true;
        return next();
      }
    }

    // Check for passport authentication
    if (req.isAuthenticated && req.isAuthenticated()) {
      req.user = req.user;
      req.passportAuth = true;
      return next();
    }

    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Authentication required'
    });
  } catch (error) {
    logger.error('Authentication middleware error:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Authentication check failed'
    });
  }
};

/**
 * Middleware to check if user has specific role
 */
const hasRole = (requiredRole) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Super admin has all roles
      if (req.user.hasRole('super_admin')) {
        return next();
      }

      // Check if user has the required role
      if (!req.user.hasRole(requiredRole)) {
        await auditService.log('access_denied', {
          userId: req.user._id,
          requiredRole,
          userRoles: req.user.roles.map(r => r.name || r),
          path: req.path,
          method: req.method
        });

        return res.status(403).json({
          error: 'Forbidden',
          message: `Role '${requiredRole}' is required`
        });
      }

      next();
    } catch (error) {
      logger.error('Role check error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Role check failed'
      });
    }
  };
};

/**
 * Middleware to check if user has any of the specified roles
 */
const hasAnyRole = (roles) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Super admin has all roles
      if (req.user.hasRole('super_admin')) {
        return next();
      }

      // Check if user has any of the required roles
      const hasRequiredRole = roles.some(role => req.user.hasRole(role));
      
      if (!hasRequiredRole) {
        await auditService.log('access_denied', {
          userId: req.user._id,
          requiredRoles: roles,
          userRoles: req.user.roles.map(r => r.name || r),
          path: req.path,
          method: req.method
        });

        return res.status(403).json({
          error: 'Forbidden',
          message: `One of the following roles is required: ${roles.join(', ')}`
        });
      }

      next();
    } catch (error) {
      logger.error('Role check error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Role check failed'
      });
    }
  };
};

/**
 * Middleware to check if user has specific permission
 */
const hasPermission = (requiredPermission) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Super admin has all permissions
      if (req.user.hasRole('super_admin') || req.user.hasPermission('*')) {
        return next();
      }

      // Check if user has the required permission
      if (!req.user.hasPermission(requiredPermission)) {
        await auditService.log('access_denied', {
          userId: req.user._id,
          requiredPermission,
          userPermissions: req.user.permissions,
          path: req.path,
          method: req.method
        });

        return res.status(403).json({
          error: 'Forbidden',
          message: `Permission '${requiredPermission}' is required`
        });
      }

      next();
    } catch (error) {
      logger.error('Permission check error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Permission check failed'
      });
    }
  };
};

/**
 * Middleware to check if user has any of the specified permissions
 */
const hasAnyPermission = (permissions) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Super admin has all permissions
      if (req.user.hasRole('super_admin') || req.user.hasPermission('*')) {
        return next();
      }

      // Check if user has any of the required permissions
      const hasRequiredPermission = permissions.some(permission => 
        req.user.hasPermission(permission)
      );
      
      if (!hasRequiredPermission) {
        await auditService.log('access_denied', {
          userId: req.user._id,
          requiredPermissions: permissions,
          userPermissions: req.user.permissions,
          path: req.path,
          method: req.method
        });

        return res.status(403).json({
          error: 'Forbidden',
          message: `One of the following permissions is required: ${permissions.join(', ')}`
        });
      }

      next();
    } catch (error) {
      logger.error('Permission check error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Permission check failed'
      });
    }
  };
};

/**
 * Middleware to check if user owns the resource or has admin role
 */
const isOwnerOrAdmin = (resourceUserIdField = 'userId') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required'
        });
      }

      // Admin can access any resource
      if (req.user.hasRole('admin') || req.user.hasRole('super_admin')) {
        return next();
      }

      // Check if user owns the resource
      const resourceUserId = req.params[resourceUserIdField] || req.body[resourceUserIdField];
      
      if (!resourceUserId) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Resource user ID not found'
        });
      }

      if (req.user._id.toString() !== resourceUserId.toString()) {
        await auditService.log('access_denied', {
          userId: req.user._id,
          resourceUserId,
          reason: 'not_owner',
          path: req.path,
          method: req.method
        });

        return res.status(403).json({
          error: 'Forbidden',
          message: 'You can only access your own resources'
        });
      }

      next();
    } catch (error) {
      logger.error('Ownership check error:', error);
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Ownership check failed'
      });
    }
  };
};

/**
 * Middleware to check if user's email is verified
 */
const requireEmailVerification = (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    if (!req.user.emailVerified) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Email verification required'
      });
    }

    next();
  } catch (error) {
    logger.error('Email verification check error:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'Email verification check failed'
    });
  }
};

/**
 * Middleware to check if 2FA is enabled and verified
 */
const require2FA = (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    if (req.user.twoFactorAuth?.enabled && !req.session?.twoFactorVerified) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Two-factor authentication required',
        requiresTwoFactor: true
      });
    }

    next();
  } catch (error) {
    logger.error('2FA check error:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: '2FA check failed'
    });
  }
};

/**
 * Middleware to log API access
 */
const logAccess = (req, res, next) => {
  const startTime = Date.now();
  
  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(...args) {
    const duration = Date.now() - startTime;
    
    // Log API access
    auditService.log('api_access', {
      userId: req.user?._id,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    originalEnd.apply(this, args);
  };

  next();
};

/**
 * Middleware to validate API key
 */
const validateApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;
    
    if (!apiKey) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'API key is required'
      });
    }

    // Validate API key format
    const cryptoUtils = require('../utils/cryptoUtils');
    if (!cryptoUtils.validateAPIKey(apiKey)) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid API key format'
      });
    }

    // Here you would typically look up the API key in the database
    // For now, we'll just validate the format
    req.apiKey = apiKey;
    next();
  } catch (error) {
    logger.error('API key validation error:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: 'API key validation failed'
    });
  }
};

module.exports = {
  authenticateToken,
  isAuthenticated,
  hasRole,
  hasAnyRole,
  hasPermission,
  hasAnyPermission,
  isOwnerOrAdmin,
  requireEmailVerification,
  require2FA,
  logAccess,
  validateApiKey
};

