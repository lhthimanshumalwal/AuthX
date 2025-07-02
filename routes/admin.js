const express = require('express');
const passport = require('passport');
const { asyncHandler } = require('../middleware/errorHandler');
const userService = require('../services/userService');
const strategyRegistry = require('../auth/strategyRegistry');
const databaseManager = require('../config/database');
const { logger } = require('../utils/logger');

const router = express.Router();

/**
 * Admin Routes
 * Provides endpoints for administrative functions
 */

// Middleware to ensure user is authenticated and has admin role
const requireAdmin = [
  passport.authenticate(['jwt', 'session'], { session: false }),
  asyncHandler(async (req, res, next) => {
    const userId = req.user._id || req.user.id;
    const hasAdminPermission = await userService.hasPermission(userId, 'admin:*');
    
    if (!hasAdminPermission) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }
    
    next();
  })
];

/**
 * GET /admin/stats
 * Get system statistics
 */
router.get('/stats', requireAdmin, asyncHandler(async (req, res) => {
  try {
    const userStats = await userService.getStats();
    const strategyStats = strategyRegistry.getStats();
    const dbStats = await databaseManager.getStats();
    const dbHealth = databaseManager.isHealthy();

    res.json({
      success: true,
      stats: {
        users: userStats,
        authentication: strategyStats,
        database: dbStats,
        health: dbHealth,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    logger.error('Admin stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve system statistics'
    });
  }
}));

/**
 * GET /admin/users
 * Get all users (paginated)
 */
router.get('/users', requireAdmin, asyncHandler(async (req, res) => {
  // This is a placeholder - in a real implementation, you'd want proper pagination
  // and filtering capabilities
  res.json({
    success: true,
    message: 'User management endpoint - implementation pending',
    note: 'This would include user listing, search, and management functions'
  });
}));

/**
 * GET /admin/strategies
 * Get authentication strategy information
 */
router.get('/strategies', requireAdmin, asyncHandler(async (req, res) => {
  const strategies = strategyRegistry.getStats();
  const validation = strategyRegistry.validate();

  res.json({
    success: true,
    strategies: strategies.strategies,
    summary: {
      total: strategies.total,
      enabled: strategies.enabled,
      disabled: strategies.disabled,
      default: strategies.default,
      types: strategies.types
    },
    validation
  });
}));

/**
 * GET /admin/health
 * Comprehensive health check
 */
router.get('/health', requireAdmin, asyncHandler(async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    checks: {}
  };

  try {
    // Database health
    const dbHealth = databaseManager.isHealthy();
    health.checks.database = dbHealth;
    
    // Authentication strategies health
    const strategyValidation = strategyRegistry.validate();
    health.checks.authentication = {
      valid: strategyValidation.valid.length > 0,
      validStrategies: strategyValidation.valid,
      invalidStrategies: strategyValidation.invalid,
      warnings: strategyValidation.warnings
    };

    // Overall health status
    if (!dbHealth.overall || strategyValidation.valid.length === 0) {
      health.status = 'unhealthy';
    } else if (strategyValidation.warnings.length > 0 || !dbHealth.redis) {
      health.status = 'degraded';
    }

    const statusCode = health.status === 'healthy' ? 200 : 
                      health.status === 'degraded' ? 200 : 503;

    res.status(statusCode).json({
      success: true,
      health
    });
  } catch (error) {
    logger.error('Health check error:', error);
    res.status(503).json({
      success: false,
      health: {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: 'Health check failed'
      }
    });
  }
}));

/**
 * POST /admin/users/:id/roles
 * Add role to user
 */
router.post('/users/:id/roles', requireAdmin, asyncHandler(async (req, res) => {
  const { id: userId } = req.params;
  const { roleId } = req.body;
  const adminId = req.user._id || req.user.id;

  if (!roleId) {
    return res.status(400).json({
      success: false,
      error: 'Role ID is required'
    });
  }

  try {
    await userService.addRole(userId, roleId, {
      changedBy: adminId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'Role added to user successfully'
    });
  } catch (error) {
    logger.error('Add role error:', error);
    res.status(400).json({
      success: false,
      error: error.message || 'Failed to add role to user'
    });
  }
}));

/**
 * DELETE /admin/users/:id/roles/:roleId
 * Remove role from user
 */
router.delete('/users/:id/roles/:roleId', requireAdmin, asyncHandler(async (req, res) => {
  const { id: userId, roleId } = req.params;
  const adminId = req.user._id || req.user.id;

  try {
    await userService.removeRole(userId, roleId, {
      changedBy: adminId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'Role removed from user successfully'
    });
  } catch (error) {
    logger.error('Remove role error:', error);
    res.status(400).json({
      success: false,
      error: error.message || 'Failed to remove role from user'
    });
  }
}));

/**
 * PUT /admin/users/:id/status
 * Update user status
 */
router.put('/admin/users/:id/status', requireAdmin, asyncHandler(async (req, res) => {
  const { id: userId } = req.params;
  const { status, reason } = req.body;
  const adminId = req.user._id || req.user.id;

  const validStatuses = ['active', 'inactive', 'suspended', 'pending'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid status. Must be one of: ' + validStatuses.join(', ')
    });
  }

  try {
    await userService.update(userId, {
      status,
      'metadata.statusChangeReason': reason,
      'metadata.statusChangedBy': adminId,
      'metadata.statusChangedAt': new Date()
    }, {
      updatedBy: adminId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'User status updated successfully'
    });
  } catch (error) {
    logger.error('Update user status error:', error);
    res.status(400).json({
      success: false,
      error: error.message || 'Failed to update user status'
    });
  }
}));

/**
 * GET /admin/audit
 * Get audit logs (placeholder)
 */
router.get('/audit', requireAdmin, asyncHandler(async (req, res) => {
  // This is a placeholder - in a real implementation, you'd want to read
  // from audit log files or database
  res.json({
    success: true,
    message: 'Audit log endpoint - implementation pending',
    note: 'This would include audit log retrieval and filtering'
  });
}));

/**
 * POST /admin/maintenance
 * Trigger maintenance tasks
 */
router.post('/maintenance', requireAdmin, asyncHandler(async (req, res) => {
  const { task } = req.body;
  const adminId = req.user._id || req.user.id;

  logger.info('Maintenance task requested', {
    task,
    requestedBy: adminId,
    ip: req.ip
  });

  switch (task) {
    case 'cleanup-sessions':
      // Placeholder for session cleanup
      res.json({
        success: true,
        message: 'Session cleanup task queued'
      });
      break;
    
    case 'refresh-strategies':
      try {
        await strategyRegistry.initialize();
        res.json({
          success: true,
          message: 'Authentication strategies refreshed'
        });
      } catch (error) {
        logger.error('Strategy refresh error:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to refresh strategies'
        });
      }
      break;
    
    default:
      res.status(400).json({
        success: false,
        error: 'Unknown maintenance task'
      });
  }
}));

module.exports = router;

