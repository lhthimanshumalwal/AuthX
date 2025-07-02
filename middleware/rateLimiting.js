const rateLimit = require('express-rate-limit');
const config = require('../config/config');
const { logger, logSecurity } = require('../utils/logger');
const databaseManager = require('../config/database');

/**
 * Rate limiting middleware configuration
 * Provides comprehensive rate limiting with Redis store support
 */

/**
 * Custom rate limit store using Redis
 */
class RedisStore {
  constructor(options = {}) {
    this.client = databaseManager.getRedisClient();
    this.prefix = options.prefix || 'rl:';
    this.windowMs = options.windowMs || 60000;
  }

  async increment(key) {
    if (!this.client) {
      // Fallback to memory store if Redis is not available
      return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
    }

    try {
      const redisKey = `${this.prefix}${key}`;
      const multi = this.client.multi();
      
      multi.incr(redisKey);
      multi.expire(redisKey, Math.ceil(this.windowMs / 1000));
      
      const results = await multi.exec();
      const totalHits = results[0][1];
      const resetTime = new Date(Date.now() + this.windowMs);
      
      return { totalHits, resetTime };
    } catch (error) {
      logger.error('Redis rate limit store error:', error);
      // Fallback to allowing the request
      return { totalHits: 1, resetTime: new Date(Date.now() + this.windowMs) };
    }
  }

  async decrement(key) {
    if (!this.client) return;

    try {
      const redisKey = `${this.prefix}${key}`;
      await this.client.decr(redisKey);
    } catch (error) {
      logger.error('Redis rate limit decrement error:', error);
    }
  }

  async resetKey(key) {
    if (!this.client) return;

    try {
      const redisKey = `${this.prefix}${key}`;
      await this.client.del(redisKey);
    } catch (error) {
      logger.error('Redis rate limit reset error:', error);
    }
  }
}

/**
 * Custom key generator that includes user ID if available
 * @param {Object} req - Express request object
 * @returns {string} Rate limit key
 */
const keyGenerator = (req) => {
  const userId = req.user ? req.user.id : null;
  const ip = req.ip || req.connection.remoteAddress;
  
  if (userId) {
    return `user:${userId}`;
  }
  
  return `ip:${ip}`;
};

/**
 * Custom rate limit handler
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const rateLimitHandler = (req, res, next) => {
  const userId = req.user ? req.user.id : null;
  const ip = req.ip || req.connection.remoteAddress;
  
  // Log rate limit violation
  logSecurity('rate_limit_exceeded', {
    userId,
    ip,
    userAgent: req.get('User-Agent'),
    path: req.path,
    method: req.method
  });

  logger.warn('Rate limit exceeded', {
    userId,
    ip,
    userAgent: req.get('User-Agent'),
    path: req.path,
    method: req.method
  });

  res.status(429).json({
    success: false,
    error: {
      message: 'Too many requests',
      code: 'RATE_LIMIT_EXCEEDED',
      status: 429,
      timestamp: new Date().toISOString(),
      retryAfter: res.get('Retry-After')
    }
  });
};

/**
 * Skip rate limiting for certain conditions
 * @param {Object} req - Express request object
 * @returns {boolean} True to skip rate limiting
 */
const skipRateLimit = (req) => {
  // Skip for health checks
  if (req.path === '/health' || req.path === '/ping') {
    return true;
  }

  // Skip for admin users (if authenticated)
  if (req.user && req.user.roles) {
    const hasAdminRole = req.user.roles.some(role => 
      role.name === 'admin' || role.name === 'super_admin'
    );
    if (hasAdminRole) {
      return true;
    }
  }

  return false;
};

/**
 * Global rate limiter
 */
const globalRateLimit = rateLimit({
  windowMs: config.rateLimiting.global.windowMs,
  max: config.rateLimiting.global.max,
  keyGenerator,
  handler: rateLimitHandler,
  skip: skipRateLimit,
  store: new RedisStore({
    prefix: 'global:',
    windowMs: config.rateLimiting.global.windowMs
  }),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      message: 'Too many requests from this IP',
      code: 'GLOBAL_RATE_LIMIT_EXCEEDED',
      status: 429
    }
  }
});

/**
 * Login rate limiter (more restrictive)
 */
const loginRateLimit = rateLimit({
  windowMs: config.rateLimiting.login.windowMs,
  max: config.rateLimiting.login.max,
  keyGenerator: (req) => {
    // Use email/username from request body if available
    const identifier = req.body.email || req.body.username || req.body.identifier;
    if (identifier) {
      return `login:${identifier.toLowerCase()}`;
    }
    return `login:ip:${req.ip}`;
  },
  handler: (req, res, next) => {
    const identifier = req.body.email || req.body.username || req.body.identifier;
    
    logSecurity('login_rate_limit_exceeded', {
      identifier,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    logger.warn('Login rate limit exceeded', {
      identifier,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      success: false,
      error: {
        message: 'Too many login attempts',
        code: 'LOGIN_RATE_LIMIT_EXCEEDED',
        status: 429,
        timestamp: new Date().toISOString(),
        retryAfter: res.get('Retry-After')
      }
    });
  },
  skip: (req) => {
    // Don't skip login rate limiting for anyone
    return false;
  },
  store: new RedisStore({
    prefix: 'login:',
    windowMs: config.rateLimiting.login.windowMs
  }),
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Registration rate limiter
 */
const registrationRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registrations per hour per IP
  keyGenerator: (req) => `register:ip:${req.ip}`,
  handler: rateLimitHandler,
  store: new RedisStore({
    prefix: 'register:',
    windowMs: 60 * 60 * 1000
  }),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      message: 'Too many registration attempts',
      code: 'REGISTRATION_RATE_LIMIT_EXCEEDED',
      status: 429
    }
  }
});

/**
 * Password reset rate limiter
 */
const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 password reset requests per hour
  keyGenerator: (req) => {
    const email = req.body.email;
    if (email) {
      return `reset:email:${email.toLowerCase()}`;
    }
    return `reset:ip:${req.ip}`;
  },
  handler: rateLimitHandler,
  store: new RedisStore({
    prefix: 'reset:',
    windowMs: 60 * 60 * 1000
  }),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      message: 'Too many password reset attempts',
      code: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
      status: 429
    }
  }
});

/**
 * API rate limiter (for API endpoints)
 */
const apiRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // 1000 requests per 15 minutes
  keyGenerator: (req) => {
    // Use API key if available, otherwise fall back to user/IP
    const apiKey = req.headers['x-api-key'];
    if (apiKey) {
      return `api:key:${apiKey}`;
    }
    
    const userId = req.user ? req.user.id : null;
    if (userId) {
      return `api:user:${userId}`;
    }
    
    return `api:ip:${req.ip}`;
  },
  handler: rateLimitHandler,
  skip: skipRateLimit,
  store: new RedisStore({
    prefix: 'api:',
    windowMs: 15 * 60 * 1000
  }),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      message: 'API rate limit exceeded',
      code: 'API_RATE_LIMIT_EXCEEDED',
      status: 429
    }
  }
});

/**
 * Create custom rate limiter
 * @param {Object} options - Rate limit options
 * @returns {Function} Rate limit middleware
 */
const createRateLimit = (options = {}) => {
  const defaultOptions = {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    keyGenerator,
    handler: rateLimitHandler,
    skip: skipRateLimit,
    standardHeaders: true,
    legacyHeaders: false
  };

  const mergedOptions = { ...defaultOptions, ...options };

  if (!mergedOptions.store && databaseManager.getRedisClient()) {
    mergedOptions.store = new RedisStore({
      prefix: options.prefix || 'custom:',
      windowMs: mergedOptions.windowMs
    });
  }

  return rateLimit(mergedOptions);
};

/**
 * Brute force protection middleware
 * @param {Object} options - Brute force options
 * @returns {Function} Middleware function
 */
const bruteForceProtection = (options = {}) => {
  const maxAttempts = options.maxAttempts || 10;
  const blockDuration = options.blockDuration || 60 * 60 * 1000; // 1 hour
  const prefix = options.prefix || 'brute:';

  return async (req, res, next) => {
    const client = databaseManager.getRedisClient();
    if (!client) {
      return next(); // Skip if Redis is not available
    }

    try {
      const key = `${prefix}${req.ip}`;
      const attempts = await client.get(key);
      
      if (attempts && parseInt(attempts) >= maxAttempts) {
        logSecurity('brute_force_blocked', {
          ip: req.ip,
          attempts: parseInt(attempts),
          userAgent: req.get('User-Agent')
        });

        return res.status(429).json({
          success: false,
          error: {
            message: 'Too many failed attempts. Please try again later.',
            code: 'BRUTE_FORCE_BLOCKED',
            status: 429,
            timestamp: new Date().toISOString()
          }
        });
      }

      next();
    } catch (error) {
      logger.error('Brute force protection error:', error);
      next(); // Continue on error
    }
  };
};

module.exports = {
  global: globalRateLimit,
  login: loginRateLimit,
  registration: registrationRateLimit,
  passwordReset: passwordResetRateLimit,
  api: apiRateLimit,
  createRateLimit,
  bruteForceProtection,
  RedisStore
};

