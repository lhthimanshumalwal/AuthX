const logger = require('../utils/logger');
const config = require('../config/config');

/**
 * Audit logging middleware
 * Logs all HTTP requests for security and compliance purposes
 */
const auditLogger = (req, res, next) => {
  // Skip audit logging if disabled
  if (!config.logging.enableAuditLogging) {
    return next();
  }

  const startTime = Date.now();
  const originalEnd = res.end;

  // Capture request data
  const requestData = {
    requestId: req.context?.requestId,
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl,
    path: req.path,
    query: req.query,
    headers: sanitizeHeaders(req.headers),
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent'),
    referer: req.get('Referer'),
    userId: null,
    sessionId: null,
    body: sanitizeBody(req.body, req.path)
  };

  // Add user information if available
  if (req.user) {
    requestData.userId = req.user._id;
    requestData.userEmail = req.user.email;
    requestData.userRoles = req.user.roles?.map(r => r.name || r) || [];
  }

  // Add session information if available
  if (req.session) {
    requestData.sessionId = req.session.id;
  }

  // Override res.end to capture response data
  res.end = function(chunk, encoding) {
    const endTime = Date.now();
    const duration = endTime - startTime;

    // Capture response data
    const responseData = {
      statusCode: res.statusCode,
      statusMessage: res.statusMessage,
      headers: sanitizeHeaders(res.getHeaders()),
      duration: duration,
      contentLength: res.get('Content-Length') || (chunk ? chunk.length : 0)
    };

    // Create audit log entry
    const auditEntry = {
      ...requestData,
      response: responseData,
      success: res.statusCode < 400,
      error: res.statusCode >= 400
    };

    // Log based on status code
    if (res.statusCode >= 500) {
      logger.error('AUDIT - Server Error', auditEntry);
    } else if (res.statusCode >= 400) {
      logger.warn('AUDIT - Client Error', auditEntry);
    } else {
      logger.info('AUDIT - Success', auditEntry);
    }

    // Log security-relevant events
    logSecurityEvents(auditEntry);

    // Call original end method
    originalEnd.call(this, chunk, encoding);
  };

  next();
};

/**
 * Sanitize headers to remove sensitive information
 */
function sanitizeHeaders(headers) {
  const sanitized = { ...headers };
  const sensitiveHeaders = [
    'authorization',
    'cookie',
    'x-api-key',
    'x-auth-token',
    'x-access-token'
  ];

  sensitiveHeaders.forEach(header => {
    if (sanitized[header]) {
      sanitized[header] = maskSensitiveValue(sanitized[header]);
    }
  });

  return sanitized;
}

/**
 * Sanitize request body to remove sensitive information
 */
function sanitizeBody(body, path) {
  if (!body || typeof body !== 'object') {
    return body;
  }

  const sanitized = { ...body };
  const sensitiveFields = [
    'password',
    'currentPassword',
    'newPassword',
    'confirmPassword',
    'token',
    'secret',
    'apiKey',
    'privateKey',
    'accessToken',
    'refreshToken'
  ];

  // Additional sensitive fields for specific endpoints
  if (path.includes('/auth/') || path.includes('/login')) {
    sensitiveFields.push('code', 'otp', 'pin');
  }

  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = maskSensitiveValue(sanitized[field]);
    }
  });

  return sanitized;
}

/**
 * Mask sensitive values for logging
 */
function maskSensitiveValue(value) {
  if (!value) return value;
  
  const str = value.toString();
  if (str.length <= 4) {
    return '****';
  } else if (str.length <= 8) {
    return str.substring(0, 2) + '****';
  } else {
    return str.substring(0, 4) + '****' + str.substring(str.length - 4);
  }
}

/**
 * Log specific security events
 */
function logSecurityEvents(auditEntry) {
  const { method, path, statusCode, userId, ip, userAgent } = auditEntry;

  // Failed authentication attempts
  if (path.includes('/auth/login') && statusCode === 401) {
    logger.security('Failed login attempt', {
      ip,
      userAgent,
      path,
      timestamp: auditEntry.timestamp
    });
  }

  // Multiple failed attempts from same IP
  if (statusCode === 429) {
    logger.security('Rate limit exceeded', {
      ip,
      userAgent,
      path,
      method,
      timestamp: auditEntry.timestamp
    });
  }

  // Suspicious activity patterns
  if (statusCode === 403) {
    logger.security('Access denied', {
      userId,
      ip,
      userAgent,
      path,
      method,
      timestamp: auditEntry.timestamp
    });
  }

  // Admin actions
  if (userId && path.includes('/admin/')) {
    logger.security('Admin action', {
      userId,
      action: `${method} ${path}`,
      ip,
      statusCode,
      timestamp: auditEntry.timestamp
    });
  }

  // Password changes
  if (path.includes('/password') && method === 'POST' && statusCode < 300) {
    logger.security('Password changed', {
      userId,
      ip,
      userAgent,
      timestamp: auditEntry.timestamp
    });
  }

  // Account modifications
  if (path.includes('/users/') && ['PUT', 'PATCH', 'DELETE'].includes(method) && statusCode < 300) {
    logger.security('Account modified', {
      userId,
      action: `${method} ${path}`,
      ip,
      timestamp: auditEntry.timestamp
    });
  }

  // Privilege escalation attempts
  if (path.includes('/roles') && method === 'POST' && statusCode < 300) {
    logger.security('Role assignment', {
      userId,
      ip,
      path,
      timestamp: auditEntry.timestamp
    });
  }
}

/**
 * Create audit log entry for custom events
 */
const logCustomEvent = (eventType, eventData, req) => {
  if (!config.logging.enableAuditLogging) {
    return;
  }

  const auditEntry = {
    eventType,
    timestamp: new Date().toISOString(),
    requestId: req?.context?.requestId,
    userId: req?.user?._id,
    userEmail: req?.user?.email,
    ip: req?.ip,
    userAgent: req?.get('User-Agent'),
    ...eventData
  };

  logger.info('AUDIT - Custom Event', auditEntry);
};

/**
 * Middleware for logging sensitive operations
 */
const logSensitiveOperation = (operationType) => {
  return (req, res, next) => {
    const originalEnd = res.end;
    
    res.end = function(chunk, encoding) {
      if (res.statusCode < 400) {
        logCustomEvent('sensitive_operation', {
          operation: operationType,
          success: true,
          details: {
            method: req.method,
            path: req.path,
            params: req.params,
            query: req.query
          }
        }, req);
      }
      
      originalEnd.call(this, chunk, encoding);
    };
    
    next();
  };
};

/**
 * Log data access events
 */
const logDataAccess = (dataType, action = 'read') => {
  return (req, res, next) => {
    const originalEnd = res.end;
    
    res.end = function(chunk, encoding) {
      if (res.statusCode < 400) {
        logCustomEvent('data_access', {
          dataType,
          action,
          resourceId: req.params.id,
          success: true
        }, req);
      }
      
      originalEnd.call(this, chunk, encoding);
    };
    
    next();
  };
};

/**
 * Cleanup old audit logs
 */
const cleanupAuditLogs = async () => {
  try {
    const retentionDays = config.logging.auditLogRetentionDays || 90;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    // This would typically clean up database records or log files
    // Implementation depends on your log storage strategy
    logger.info(`Audit log cleanup completed for logs older than ${cutoffDate.toISOString()}`);
  } catch (error) {
    logger.error('Error cleaning up audit logs:', error);
  }
};

module.exports = {
  auditLogger,
  logCustomEvent,
  logSensitiveOperation,
  logDataAccess,
  cleanupAuditLogs
};

