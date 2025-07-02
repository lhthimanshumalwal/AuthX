const helmet = require('helmet');
const { logger, logSecurity } = require('../utils/logger');
const config = require('../config/config');

/**
 * Security middleware collection
 * Provides comprehensive security headers and input sanitization
 */

/**
 * Add security headers middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const addSecurityHeaders = (req, res, next) => {
  // Remove server information
  res.removeHeader('X-Powered-By');
  
  // Add custom security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  // Add HSTS header in production
  if (config.server.env === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  
  next();
};

/**
 * Input sanitization middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const sanitizeInput = (req, res, next) => {
  try {
    // Sanitize request body
    if (req.body && typeof req.body === 'object') {
      req.body = sanitizeObject(req.body);
    }
    
    // Sanitize query parameters
    if (req.query && typeof req.query === 'object') {
      req.query = sanitizeObject(req.query);
    }
    
    // Sanitize URL parameters
    if (req.params && typeof req.params === 'object') {
      req.params = sanitizeObject(req.params);
    }
    
    next();
  } catch (error) {
    logger.error('Input sanitization error:', error);
    next(error);
  }
};

/**
 * Sanitize object recursively
 * @param {Object} obj - Object to sanitize
 * @returns {Object} Sanitized object
 */
const sanitizeObject = (obj) => {
  if (obj === null || typeof obj !== 'object') {
    return sanitizeValue(obj);
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }
  
  const sanitized = {};
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) {
      const sanitizedKey = sanitizeValue(key);
      sanitized[sanitizedKey] = sanitizeObject(obj[key]);
    }
  }
  
  return sanitized;
};

/**
 * Sanitize individual value
 * @param {*} value - Value to sanitize
 * @returns {*} Sanitized value
 */
const sanitizeValue = (value) => {
  if (typeof value !== 'string') {
    return value;
  }
  
  // Remove potentially dangerous characters
  return value
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '') // Remove iframe tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .replace(/\0/g, '') // Remove null bytes
    .trim();
};

/**
 * SQL injection protection middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const sqlInjectionProtection = (req, res, next) => {
  const sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/gi,
    /((\%27)|(\'))\s*((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi, // ' or
    /((\%27)|(\'))\s*((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi, // ' OR
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi, // word'or
    /((\%27)|(\'))\s*\-\-/gi, // '--
    /((\%27)|(\'))\s*((\%23)|#)/gi, // '#
    /((\%3D)|(=))[^\n]*((\%27)|(\')|((\%3B)|(;)))/gi, // ='
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/gi, // word'or
    /((\%27)|(\'))\s*((\%6F)|o|(\%4F))((\%72)|r|(\%52))\s*((\%3D)|(=))/gi, // ' or =
    /((\%27)|(\'))\s*1\s*((\%3D)|(=))\s*1/gi // ' 1=1
  ];
  
  const checkForSQLInjection = (obj, path = '') => {
    if (typeof obj === 'string') {
      for (const pattern of sqlPatterns) {
        if (pattern.test(obj)) {
          logSecurity('sql_injection_attempt', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            path: req.path,
            field: path,
            value: obj.substring(0, 100), // Log first 100 chars
            userId: req.user ? req.user.id : null
          });
          
          const error = new Error('Potential SQL injection detected');
          error.status = 400;
          error.code = 'SQL_INJECTION_DETECTED';
          throw error;
        }
      }
    } else if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          checkForSQLInjection(obj[key], path ? `${path}.${key}` : key);
        }
      }
    }
  };
  
  try {
    // Check request body
    if (req.body) {
      checkForSQLInjection(req.body, 'body');
    }
    
    // Check query parameters
    if (req.query) {
      checkForSQLInjection(req.query, 'query');
    }
    
    // Check URL parameters
    if (req.params) {
      checkForSQLInjection(req.params, 'params');
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * NoSQL injection protection middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const noSQLInjectionProtection = (req, res, next) => {
  const checkForNoSQLInjection = (obj, path = '') => {
    if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          // Check for MongoDB operators
          if (key.startsWith('$')) {
            logSecurity('nosql_injection_attempt', {
              ip: req.ip,
              userAgent: req.get('User-Agent'),
              path: req.path,
              field: path ? `${path}.${key}` : key,
              operator: key,
              userId: req.user ? req.user.id : null
            });
            
            const error = new Error('Potential NoSQL injection detected');
            error.status = 400;
            error.code = 'NOSQL_INJECTION_DETECTED';
            throw error;
          }
          
          checkForNoSQLInjection(obj[key], path ? `${path}.${key}` : key);
        }
      }
    }
  };
  
  try {
    // Check request body
    if (req.body) {
      checkForNoSQLInjection(req.body, 'body');
    }
    
    // Check query parameters
    if (req.query) {
      checkForNoSQLInjection(req.query, 'query');
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * XSS protection middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const xssProtection = (req, res, next) => {
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<img[^>]+src[\\s]*=[\\s]*["\']javascript:/gi,
    /<[^>]*style[\\s]*=[\\s]*["\'][^"\']*expression[\\s]*\(/gi
  ];
  
  const checkForXSS = (obj, path = '') => {
    if (typeof obj === 'string') {
      for (const pattern of xssPatterns) {
        if (pattern.test(obj)) {
          logSecurity('xss_attempt', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            path: req.path,
            field: path,
            value: obj.substring(0, 100),
            userId: req.user ? req.user.id : null
          });
          
          const error = new Error('Potential XSS attack detected');
          error.status = 400;
          error.code = 'XSS_DETECTED';
          throw error;
        }
      }
    } else if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          checkForXSS(obj[key], path ? `${path}.${key}` : key);
        }
      }
    }
  };
  
  try {
    // Check request body
    if (req.body) {
      checkForXSS(req.body, 'body');
    }
    
    // Check query parameters
    if (req.query) {
      checkForXSS(req.query, 'query');
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * CSRF protection middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const csrfProtection = (req, res, next) => {
  // Skip CSRF protection for API endpoints with API keys
  if (req.headers['x-api-key']) {
    return next();
  }
  
  // Skip for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  
  const token = req.headers['x-csrf-token'] || req.body._csrf;
  const sessionToken = req.session && req.session.csrfToken;
  
  if (!token || !sessionToken || token !== sessionToken) {
    logSecurity('csrf_attack', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      providedToken: token ? 'present' : 'missing',
      sessionToken: sessionToken ? 'present' : 'missing',
      userId: req.user ? req.user.id : null
    });
    
    const error = new Error('Invalid CSRF token');
    error.status = 403;
    error.code = 'CSRF_TOKEN_INVALID';
    return next(error);
  }
  
  next();
};

/**
 * Request size limit middleware
 * @param {Object} options - Size limit options
 * @returns {Function} Middleware function
 */
const requestSizeLimit = (options = {}) => {
  const maxSize = options.maxSize || 10 * 1024 * 1024; // 10MB default
  
  return (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'], 10);
    
    if (contentLength && contentLength > maxSize) {
      logSecurity('request_size_exceeded', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        contentLength,
        maxSize,
        userId: req.user ? req.user.id : null
      });
      
      const error = new Error('Request entity too large');
      error.status = 413;
      error.code = 'REQUEST_TOO_LARGE';
      return next(error);
    }
    
    next();
  };
};

/**
 * IP whitelist middleware
 * @param {Array} whitelist - Array of allowed IP addresses/ranges
 * @returns {Function} Middleware function
 */
const ipWhitelist = (whitelist = []) => {
  return (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (whitelist.length === 0) {
      return next(); // No whitelist configured
    }
    
    const isAllowed = whitelist.some(ip => {
      if (ip.includes('/')) {
        // CIDR notation support would require additional library
        return false;
      }
      return clientIP === ip;
    });
    
    if (!isAllowed) {
      logSecurity('ip_not_whitelisted', {
        ip: clientIP,
        userAgent: req.get('User-Agent'),
        path: req.path,
        whitelist,
        userId: req.user ? req.user.id : null
      });
      
      const error = new Error('Access denied');
      error.status = 403;
      error.code = 'IP_NOT_ALLOWED';
      return next(error);
    }
    
    next();
  };
};

/**
 * Security audit middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const securityAudit = (req, res, next) => {
  // Log suspicious patterns
  const suspiciousPatterns = [
    /\.\.\//g, // Directory traversal
    /\/etc\/passwd/g, // System file access
    /\/proc\//g, // Process information
    /cmd\.exe/g, // Windows command execution
    /powershell/g, // PowerShell execution
    /base64_decode/g, // Base64 decode (potential payload)
    /eval\(/g, // Code evaluation
    /system\(/g, // System command execution
    /exec\(/g // Command execution
  ];
  
  const checkSuspiciousActivity = (value, source) => {
    if (typeof value === 'string') {
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(value)) {
          logSecurity('suspicious_activity', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            path: req.path,
            source,
            pattern: pattern.toString(),
            value: value.substring(0, 100),
            userId: req.user ? req.user.id : null
          });
        }
      }
    }
  };
  
  // Check URL
  checkSuspiciousActivity(req.url, 'url');
  
  // Check headers
  Object.keys(req.headers).forEach(header => {
    checkSuspiciousActivity(req.headers[header], `header:${header}`);
  });
  
  // Check body
  if (req.body && typeof req.body === 'object') {
    JSON.stringify(req.body).split('').forEach((char, index) => {
      if (index < 1000) { // Only check first 1000 characters
        checkSuspiciousActivity(char, 'body');
      }
    });
  }
  
  next();
};

module.exports = {
  addSecurityHeaders,
  sanitizeInput,
  sqlInjectionProtection,
  noSQLInjectionProtection,
  xssProtection,
  csrfProtection,
  requestSizeLimit,
  ipWhitelist,
  securityAudit,
  sanitizeObject,
  sanitizeValue
};

