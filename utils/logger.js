const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for log messages
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({
    format: 'HH:mm:ss'
  }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta)}`;
    }
    return msg;
  })
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'authx' },
  transports: [
    // Write all logs to combined.log
    new winston.transports.File({
      filename: path.join(logsDir, 'app.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      tailable: true
    }),
    
    // Write error logs to error.log
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      tailable: true
    })
  ],
  
  // Handle uncaught exceptions
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'exceptions.log')
    })
  ],
  
  // Handle unhandled promise rejections
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'rejections.log')
    })
  ]
});

// Add console transport for development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat
  }));
}

// Create audit logger for authentication events
const auditLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { type: 'audit' },
  transports: [
    new winston.transports.File({
      filename: path.join(logsDir, 'audit.log'),
      maxsize: 10485760, // 10MB
      maxFiles: 10,
      tailable: true
    })
  ]
});

// Audit logging functions
const audit = {
  /**
   * Log authentication attempt
   */
  authAttempt: (data) => {
    auditLogger.info('Authentication attempt', {
      event: 'auth_attempt',
      ...data
    });
  },

  /**
   * Log successful authentication
   */
  authSuccess: (data) => {
    auditLogger.info('Authentication successful', {
      event: 'auth_success',
      ...data
    });
  },

  /**
   * Log failed authentication
   */
  authFailure: (data) => {
    auditLogger.warn('Authentication failed', {
      event: 'auth_failure',
      ...data
    });
  },

  /**
   * Log user registration
   */
  userRegistration: (data) => {
    auditLogger.info('User registration', {
      event: 'user_registration',
      ...data
    });
  },

  /**
   * Log password change
   */
  passwordChange: (data) => {
    auditLogger.info('Password change', {
      event: 'password_change',
      ...data
    });
  },

  /**
   * Log role change
   */
  roleChange: (data) => {
    auditLogger.info('Role change', {
      event: 'role_change',
      ...data
    });
  },

  /**
   * Log permission change
   */
  permissionChange: (data) => {
    auditLogger.info('Permission change', {
      event: 'permission_change',
      ...data
    });
  },

  /**
   * Log security event
   */
  securityEvent: (data) => {
    auditLogger.warn('Security event', {
      event: 'security_event',
      ...data
    });
  },

  /**
   * Log admin action
   */
  adminAction: (data) => {
    auditLogger.info('Admin action', {
      event: 'admin_action',
      ...data
    });
  },

  /**
   * Log token events
   */
  tokenEvent: (data) => {
    auditLogger.info('Token event', {
      event: 'token_event',
      ...data
    });
  }
};

// Performance logging
const performance = {
  /**
   * Log performance metrics
   */
  metric: (name, value, unit = 'ms', metadata = {}) => {
    logger.info('Performance metric', {
      metric: name,
      value,
      unit,
      ...metadata
    });
  },

  /**
   * Time a function execution
   */
  time: (name) => {
    const start = Date.now();
    return {
      end: (metadata = {}) => {
        const duration = Date.now() - start;
        performance.metric(name, duration, 'ms', metadata);
        return duration;
      }
    };
  }
};

// Request logging middleware
const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  // Log request
  logger.info('HTTP Request', {
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user ? req.user.id : null
  });

  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info('HTTP Response', {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userId: req.user ? req.user.id : null
    });
  });

  next();
};

// Error logging helper
const logError = (error, context = {}) => {
  logger.error('Application error', {
    message: error.message,
    stack: error.stack,
    ...context
  });
};

// Security logging helper
const logSecurity = (event, data = {}) => {
  logger.warn('Security event', {
    event,
    timestamp: new Date().toISOString(),
    ...data
  });
  
  // Also log to audit
  audit.securityEvent({ event, ...data });
};

module.exports = {
  logger,
  audit,
  performance,
  requestLogger,
  logError,
  logSecurity
};

