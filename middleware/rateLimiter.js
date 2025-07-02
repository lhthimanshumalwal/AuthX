const rateLimit = require('express-rate-limit');
const config = require('../config/config');
const logger = require('../utils/logger');
const auditService = require('../services/auditService');

// Custom key generator for user-specific rate limiting
const generateKey = (req) => {
  // Use user ID if authenticated, otherwise use IP
  if (req.user && req.user._id) {
    return `user:${req.user._id}`;
  }
  return `ip:${req.ip}`;
};

// Custom handler for rate limit exceeded
const rateLimitHandler = (req, res) => {
  const key = generateKey(req);
  
  logger.warn(`Rate limit exceeded for ${key}`, {
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Log security event
  auditService.log('rate_limit_exceeded', {
    userId: req.user?._id,
    key,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(429).json({
    error: 'Too Many Requests',
    message: 'Rate limit exceeded. Please try again later.',
    retryAfter: Math.round(req.rateLimit.resetTime / 1000)
  });
};

// Skip rate limiting for certain conditions
const skipRateLimit = (req) => {
  // Skip for health checks
  if (req.path === '/health') {
    return true;
  }
  
  // Skip for super admins (optional)
  if (req.user && req.user.hasRole && req.user.hasRole('super_admin')) {
    return true;
  }
  
  return false;
};

// General API rate limiter
const general = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  message: config.rateLimit.message,
  standardHeaders: config.rateLimit.standardHeaders,
  legacyHeaders: config.rateLimit.legacyHeaders,
  keyGenerator: generateKey,
  handler: rateLimitHandler,
  skip: skipRateLimit,
  onLimitReached: (req, res, options) => {
    logger.warn(`Rate limit reached for ${generateKey(req)}`, {
      path: req.path,
      method: req.method,
      limit: options.max,
      windowMs: options.windowMs
    });
  }
});

// Strict rate limiter for authentication endpoints
const login = rateLimit({
  windowMs: config.loginRateLimit.windowMs,
  max: config.loginRateLimit.max,
  message: config.loginRateLimit.message,
  skipSuccessfulRequests: config.loginRateLimit.skipSuccessfulRequests,
  keyGenerator: (req) => {
    // Use email/username if provided, otherwise IP
    const identifier = req.body.email || req.body.username || req.ip;
    return `login:${identifier}`;
  },
  handler: (req, res) => {
    const identifier = req.body.email || req.body.username || req.ip;
    
    logger.warn(`Login rate limit exceeded for ${identifier}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Log security event
    auditService.log('login_rate_limit_exceeded', {
      identifier,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Too many login attempts. Please try again later.',
      retryAfter: Math.round(req.rateLimit.resetTime / 1000)
    });
  },
  skip: skipRateLimit
});

// Rate limiter for registration
const register = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 registrations per hour per IP
  message: 'Too many registration attempts. Please try again later.',
  keyGenerator: (req) => `register:${req.ip}`,
  handler: (req, res) => {
    logger.warn(`Registration rate limit exceeded for IP: ${req.ip}`, {
      userAgent: req.get('User-Agent')
    });

    auditService.log('registration_rate_limit_exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Too many registration attempts. Please try again later.',
      retryAfter: Math.round(req.rateLimit.resetTime / 1000)
    });
  },
  skip: skipRateLimit
});

// Rate limiter for password reset requests
const passwordReset = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 password reset requests per hour per email
  message: 'Too many password reset requests. Please try again later.',
  keyGenerator: (req) => {
    const email = req.body.email || req.ip;
    return `password-reset:${email}`;
  },
  handler: (req, res) => {
    const email = req.body.email || 'unknown';
    
    logger.warn(`Password reset rate limit exceeded for: ${email}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    auditService.log('password_reset_rate_limit_exceeded', {
      email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Too many password reset requests. Please try again later.',
      retryAfter: Math.round(req.rateLimit.resetTime / 1000)
    });
  },
  skip: skipRateLimit
});

// Rate limiter for email verification requests
const emailVerification = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 verification emails per hour per user
  message: 'Too many email verification requests. Please try again later.',
  keyGenerator: (req) => {
    const userId = req.user?._id || req.ip;
    return `email-verification:${userId}`;
  },
  handler: (req, res) => {
    logger.warn(`Email verification rate limit exceeded`, {
      userId: req.user?._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    auditService.log('email_verification_rate_limit_exceeded', {
      userId: req.user?._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Too many email verification requests. Please try again later.',
      retryAfter: Math.round(req.rateLimit.resetTime / 1000)
    });
  },
  skip: skipRateLimit
});

// Rate limiter for 2FA attempts
const twoFactor = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per 15 minutes
  message: 'Too many 2FA attempts. Please try again later.',
  keyGenerator: (req) => {
    const userId = req.user?._id || req.session?.userId || req.ip;
    return `2fa:${userId}`;
  },
  handler: (req, res) => {
    logger.warn(`2FA rate limit exceeded`, {
      userId: req.user?._id,
      sessionUserId: req.session?.userId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    auditService.log('2fa_rate_limit_exceeded', {
      userId: req.user?._id,
      sessionUserId: req.session?.userId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Too many 2FA attempts. Please try again later.',
      retryAfter: Math.round(req.rateLimit.resetTime / 1000)
    });
  },
  skip: skipRateLimit
});

// Rate limiter for API endpoints
const api = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // 1000 requests per 15 minutes per user/IP
  message: 'API rate limit exceeded. Please try again later.',
  keyGenerator: generateKey,
  handler: rateLimitHandler,
  skip: skipRateLimit
});

// Rate limiter for file uploads
const upload = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 uploads per hour per user
  message: 'Upload rate limit exceeded. Please try again later.',
  keyGenerator: (req) => {
    const userId = req.user?._id || req.ip;
    return `upload:${userId}`;
  },
  handler: (req, res) => {
    logger.warn(`Upload rate limit exceeded`, {
      userId: req.user?._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    auditService.log('upload_rate_limit_exceeded', {
      userId: req.user?._id,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Upload rate limit exceeded. Please try again later.',
      retryAfter: Math.round(req.rateLimit.resetTime / 1000)
    });
  },
  skip: skipRateLimit
});

// Dynamic rate limiter based on user tier/plan
const createDynamicRateLimit = (getUserLimit) => {
  return rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: async (req) => {
      try {
        if (typeof getUserLimit === 'function') {
          return await getUserLimit(req);
        }
        return getUserLimit || 100;
      } catch (error) {
        logger.error('Error getting user rate limit:', error);
        return 100; // Default limit
      }
    },
    keyGenerator: generateKey,
    handler: rateLimitHandler,
    skip: skipRateLimit
  });
};

module.exports = {
  general,
  login,
  register,
  passwordReset,
  emailVerification,
  twoFactor,
  api,
  upload,
  createDynamicRateLimit
};

