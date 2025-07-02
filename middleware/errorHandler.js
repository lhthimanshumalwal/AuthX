const { logger } = require('../utils/logger');
const config = require('../config/config');

/**
 * Error handling middleware for Express applications
 * Provides comprehensive error handling with proper logging and response formatting
 */

/**
 * Not Found (404) handler
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const notFoundHandler = (req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  error.status = 404;
  error.code = 'NOT_FOUND';
  
  logger.warn('Route not found', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user ? req.user.id : null
  });
  
  next(error);
};

/**
 * Global error handler
 * @param {Error} err - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const errorHandler = (err, req, res, next) => {
  // Default error properties
  let error = {
    message: err.message || 'Internal Server Error',
    status: err.status || err.statusCode || 500,
    code: err.code || 'INTERNAL_ERROR',
    timestamp: new Date().toISOString(),
    path: req.originalUrl,
    method: req.method
  };

  // Handle specific error types
  if (err.name === 'ValidationError') {
    // Mongoose validation error
    error = handleValidationError(err);
  } else if (err.name === 'CastError') {
    // Mongoose cast error (invalid ObjectId)
    error = handleCastError(err);
  } else if (err.code === 11000) {
    // MongoDB duplicate key error
    error = handleDuplicateKeyError(err);
  } else if (err.name === 'JsonWebTokenError') {
    // JWT error
    error = handleJWTError(err);
  } else if (err.name === 'TokenExpiredError') {
    // JWT expired error
    error = handleTokenExpiredError(err);
  } else if (err.name === 'MulterError') {
    // File upload error
    error = handleMulterError(err);
  } else if (err.type === 'entity.parse.failed') {
    // JSON parse error
    error = handleJSONParseError(err);
  } else if (err.code === 'LIMIT_FILE_SIZE') {
    // File size limit error
    error = handleFileSizeError(err);
  }

  // Log error based on severity
  const logData = {
    error: {
      message: error.message,
      status: error.status,
      code: error.code,
      stack: err.stack
    },
    request: {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user ? req.user.id : null,
      body: req.body && Object.keys(req.body).length > 0 ? sanitizeRequestBody(req.body) : undefined,
      params: req.params && Object.keys(req.params).length > 0 ? req.params : undefined,
      query: req.query && Object.keys(req.query).length > 0 ? req.query : undefined
    }
  };

  if (error.status >= 500) {
    logger.error('Server error occurred', logData);
  } else if (error.status >= 400) {
    logger.warn('Client error occurred', logData);
  } else {
    logger.info('Request completed with error', logData);
  }

  // Prepare response
  const response = {
    success: false,
    error: {
      message: error.message,
      code: error.code,
      status: error.status,
      timestamp: error.timestamp
    }
  };

  // Add additional error details in development
  if (config.server.env === 'development') {
    response.error.stack = err.stack;
    response.error.path = error.path;
    response.error.method = error.method;
    
    if (error.details) {
      response.error.details = error.details;
    }
  }

  // Add request ID if available
  if (req.id) {
    response.error.requestId = req.id;
  }

  // Send error response
  res.status(error.status).json(response);
};

/**
 * Handle Mongoose validation errors
 * @param {Error} err - Validation error
 * @returns {Object} Formatted error
 */
const handleValidationError = (err) => {
  const errors = Object.values(err.errors).map(error => ({
    field: error.path,
    message: error.message,
    value: error.value
  }));

  return {
    message: 'Validation failed',
    status: 400,
    code: 'VALIDATION_ERROR',
    details: errors
  };
};

/**
 * Handle Mongoose cast errors
 * @param {Error} err - Cast error
 * @returns {Object} Formatted error
 */
const handleCastError = (err) => {
  return {
    message: `Invalid ${err.path}: ${err.value}`,
    status: 400,
    code: 'INVALID_ID'
  };
};

/**
 * Handle MongoDB duplicate key errors
 * @param {Error} err - Duplicate key error
 * @returns {Object} Formatted error
 */
const handleDuplicateKeyError = (err) => {
  const field = Object.keys(err.keyValue)[0];
  const value = err.keyValue[field];
  
  return {
    message: `${field} '${value}' already exists`,
    status: 409,
    code: 'DUPLICATE_ENTRY',
    details: {
      field,
      value
    }
  };
};

/**
 * Handle JWT errors
 * @param {Error} err - JWT error
 * @returns {Object} Formatted error
 */
const handleJWTError = (err) => {
  return {
    message: 'Invalid token',
    status: 401,
    code: 'INVALID_TOKEN'
  };
};

/**
 * Handle JWT expired errors
 * @param {Error} err - Token expired error
 * @returns {Object} Formatted error
 */
const handleTokenExpiredError = (err) => {
  return {
    message: 'Token expired',
    status: 401,
    code: 'TOKEN_EXPIRED'
  };
};

/**
 * Handle Multer errors
 * @param {Error} err - Multer error
 * @returns {Object} Formatted error
 */
const handleMulterError = (err) => {
  let message = 'File upload error';
  let code = 'UPLOAD_ERROR';

  switch (err.code) {
    case 'LIMIT_FILE_SIZE':
      message = 'File too large';
      code = 'FILE_TOO_LARGE';
      break;
    case 'LIMIT_FILE_COUNT':
      message = 'Too many files';
      code = 'TOO_MANY_FILES';
      break;
    case 'LIMIT_UNEXPECTED_FILE':
      message = 'Unexpected file field';
      code = 'UNEXPECTED_FILE';
      break;
  }

  return {
    message,
    status: 400,
    code
  };
};

/**
 * Handle JSON parse errors
 * @param {Error} err - JSON parse error
 * @returns {Object} Formatted error
 */
const handleJSONParseError = (err) => {
  return {
    message: 'Invalid JSON in request body',
    status: 400,
    code: 'INVALID_JSON'
  };
};

/**
 * Handle file size errors
 * @param {Error} err - File size error
 * @returns {Object} Formatted error
 */
const handleFileSizeError = (err) => {
  return {
    message: 'File size exceeds limit',
    status: 413,
    code: 'FILE_TOO_LARGE'
  };
};

/**
 * Sanitize request body for logging (remove sensitive data)
 * @param {Object} body - Request body
 * @returns {Object} Sanitized body
 */
const sanitizeRequestBody = (body) => {
  const sensitiveFields = [
    'password',
    'confirmPassword',
    'currentPassword',
    'newPassword',
    'token',
    'secret',
    'apiKey',
    'privateKey',
    'accessToken',
    'refreshToken'
  ];

  const sanitized = { ...body };

  const sanitizeObject = (obj) => {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (sensitiveFields.some(field => key.toLowerCase().includes(field.toLowerCase()))) {
          obj[key] = '[REDACTED]';
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          sanitizeObject(obj[key]);
        }
      }
    }
  };

  sanitizeObject(sanitized);
  return sanitized;
};

/**
 * Async error wrapper
 * Wraps async route handlers to catch errors and pass them to error handler
 * @param {Function} fn - Async function to wrap
 * @returns {Function} Wrapped function
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Create custom error
 * @param {string} message - Error message
 * @param {number} status - HTTP status code
 * @param {string} code - Error code
 * @returns {Error} Custom error
 */
const createError = (message, status = 500, code = 'INTERNAL_ERROR') => {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
};

/**
 * Rate limit error handler
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const rateLimitHandler = (req, res, next) => {
  const error = createError('Too many requests', 429, 'RATE_LIMIT_EXCEEDED');
  next(error);
};

module.exports = {
  notFoundHandler,
  errorHandler,
  asyncHandler,
  createError,
  rateLimitHandler
};

