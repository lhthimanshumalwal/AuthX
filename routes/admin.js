const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const userService = require('../services/userService');
const auditService = require('../services/auditService');
const emailService = require('../services/emailService');
const logger = require('../utils/logger');
const { getDatabaseHealth } = require('../utils/database');
const { 
  isAuthenticated, 
  hasRole, 
  hasPermission 
} = require('../middleware/authMiddleware');
const { logSensitiveOperation } = require('../middleware/auditLogger');

const router = express.Router();

/**
 * @route GET /api/admin/dashboard
 * @desc Get admin dashboard data
 * @access Private (Admin)
 */
router.get('/dashboard',
  isAuthenticated,
  hasRole('admin'),
  async (req, res) => {
    try {
      // Get user statistics
      const userStats = await userService.getUserStats();
      
      // Get audit statistics
      const auditStats = await auditService.getStatistics('24h');
      
      // Get database health
      const dbHealth = await getDatabaseHealth();
      
      // Get system info
      const systemInfo = {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: process.version,
        platform: process.platform,
        environment: process.env.NODE_ENV || 'development'
      };

      res.json({
        dashboard: {
          userStats,
          auditStats,
          dbHealth: {
            connected: dbHealth.connected,
            collections: Object.keys(dbHealth.collections || {}).length,
            totalObjects: dbHealth.stats?.objects || 0
          },
          systemInfo
        }
      });
    } catch (error) {
      logger.error('Get dashboard error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get dashboard data'
      });
    }
  }
);

/**
 * @route GET /api/admin/users
 * @desc Get all users with advanced filtering
 * @access Private (Admin)
 */
router.get('/users',
  isAuthenticated,
  hasRole('admin'),
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('search').optional().trim().isLength({ max: 100 }).withMessage('Search term must be less than 100 characters'),
    query('status').optional().isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status'),
    query('role').optional().trim().isLength({ max: 50 }).withMessage('Role must be less than 50 characters'),
    query('emailVerified').optional().isBoolean().withMessage('Email verified must be a boolean'),
    query('twoFactorEnabled').optional().isBoolean().withMessage('Two factor enabled must be a boolean'),
    query('sortBy').optional().isIn(['createdAt', 'updatedAt', 'lastLogin', 'email', 'status']).withMessage('Invalid sort field'),
    query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc')
  ],
  logSensitiveOperation('admin_user_list'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid query parameters',
          details: errors.array()
        });
      }

      const options = {
        page: parseInt(req.query.page) || 1,
        limit: parseInt(req.query.limit) || 20,
        search: req.query.search || '',
        status: req.query.status || '',
        role: req.query.role || '',
        sortBy: req.query.sortBy || 'createdAt',
        sortOrder: req.query.sortOrder || 'desc'
      };

      const result = await userService.getUsers(options);

      res.json({
        users: result.users.map(user => ({
          id: user._id,
          email: user.email,
          username: user.username,
          profile: user.profile,
          roles: user.roles.map(r => r.name || r),
          status: user.status,
          emailVerified: user.emailVerified,
          twoFactorEnabled: user.twoFactorAuth?.enabled || false,
          lastLogin: user.lastLogin,
          loginAttempts: user.loginAttempts,
          isLocked: user.isLocked,
          lockUntil: user.lockUntil,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
          authProviders: user.authProviders,
          activeSessions: user.activeSessions?.length || 0
        })),
        pagination: result.pagination
      });
    } catch (error) {
      logger.error('Admin get users error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get users'
      });
    }
  }
);

/**
 * @route PUT /api/admin/users/:id/status
 * @desc Update user status
 * @access Private (Admin)
 */
router.put('/users/:id/status',
  isAuthenticated,
  hasRole('admin'),
  [
    param('id').isMongoId().withMessage('Invalid user ID'),
    body('status').isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status')
  ],
  logSensitiveOperation('admin_user_status_change'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: errors.array()
        });
      }

      const { status } = req.body;

      // Prevent admin from suspending themselves
      if (req.params.id === req.user._id.toString() && status === 'suspended') {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Cannot suspend your own account'
        });
      }

      const updatedUser = await userService.updateUser(req.params.id, { status }, req.user._id);

      if (!updatedUser) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'User not found'
        });
      }

      // Log status change
      await auditService.log('admin_user_status_changed', {
        adminId: req.user._id,
        targetUserId: updatedUser._id,
        oldStatus: updatedUser.status,
        newStatus: status,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        message: 'User status updated successfully',
        user: {
          id: updatedUser._id,
          email: updatedUser.email,
          status: updatedUser.status
        }
      });
    } catch (error) {
      logger.error('Admin update user status error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update user status'
      });
    }
  }
);

/**
 * @route POST /api/admin/users/:id/unlock
 * @desc Unlock user account
 * @access Private (Admin)
 */
router.post('/users/:id/unlock',
  isAuthenticated,
  hasRole('admin'),
  [
    param('id').isMongoId().withMessage('Invalid user ID')
  ],
  logSensitiveOperation('admin_user_unlock'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid user ID'
        });
      }

      const user = await userService.getUserById(req.params.id);
      
      if (!user) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'User not found'
        });
      }

      // Reset login attempts and unlock
      await user.resetLoginAttempts();

      // Log unlock action
      await auditService.log('admin_user_unlocked', {
        adminId: req.user._id,
        targetUserId: user._id,
        targetEmail: user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        message: 'User account unlocked successfully',
        user: {
          id: user._id,
          email: user.email,
          isLocked: false
        }
      });
    } catch (error) {
      logger.error('Admin unlock user error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to unlock user account'
      });
    }
  }
);

/**
 * @route POST /api/admin/users/:id/send-verification
 * @desc Send verification email to user
 * @access Private (Admin)
 */
router.post('/users/:id/send-verification',
  isAuthenticated,
  hasRole('admin'),
  [
    param('id').isMongoId().withMessage('Invalid user ID')
  ],
  logSensitiveOperation('admin_send_verification'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid user ID'
        });
      }

      const user = await userService.getUserById(req.params.id);
      
      if (!user) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'User not found'
        });
      }

      if (user.emailVerified) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'User email is already verified'
        });
      }

      // Generate verification token
      const token = user.generateEmailVerificationToken();
      await user.save();

      // Send verification email
      await emailService.sendVerificationEmail(user);

      // Log action
      await auditService.log('admin_verification_email_sent', {
        adminId: req.user._id,
        targetUserId: user._id,
        targetEmail: user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        message: 'Verification email sent successfully'
      });
    } catch (error) {
      logger.error('Admin send verification error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to send verification email'
      });
    }
  }
);

/**
 * @route GET /api/admin/audit-logs
 * @desc Get audit logs
 * @access Private (Admin)
 */
router.get('/audit-logs',
  isAuthenticated,
  hasRole('admin'),
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('action').optional().trim().isLength({ max: 50 }).withMessage('Action must be less than 50 characters'),
    query('userId').optional().isMongoId().withMessage('Invalid user ID'),
    query('startDate').optional().isISO8601().withMessage('Start date must be a valid ISO date'),
    query('endDate').optional().isISO8601().withMessage('End date must be a valid ISO date')
  ],
  logSensitiveOperation('admin_audit_log_access'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid query parameters',
          details: errors.array()
        });
      }

      const filters = {
        limit: parseInt(req.query.limit) || 50,
        offset: (parseInt(req.query.page) - 1 || 0) * (parseInt(req.query.limit) || 50),
        action: req.query.action,
        userId: req.query.userId,
        startDate: req.query.startDate,
        endDate: req.query.endDate
      };

      const result = await auditService.getEvents(filters);

      res.json({
        events: result.events,
        pagination: {
          total: result.total,
          limit: result.limit,
          offset: result.offset,
          page: Math.floor(result.offset / result.limit) + 1,
          pages: Math.ceil(result.total / result.limit)
        }
      });
    } catch (error) {
      logger.error('Admin get audit logs error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get audit logs'
      });
    }
  }
);

/**
 * @route GET /api/admin/audit-logs/stats
 * @desc Get audit log statistics
 * @access Private (Admin)
 */
router.get('/audit-logs/stats',
  isAuthenticated,
  hasRole('admin'),
  [
    query('timeframe').optional().isIn(['1h', '24h', '7d', '30d']).withMessage('Invalid timeframe')
  ],
  async (req, res) => {
    try {
      const timeframe = req.query.timeframe || '24h';
      const stats = await auditService.getStatistics(timeframe);

      res.json({
        stats
      });
    } catch (error) {
      logger.error('Admin get audit stats error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get audit statistics'
      });
    }
  }
);

/**
 * @route GET /api/admin/security-events
 * @desc Get security events
 * @access Private (Admin)
 */
router.get('/security-events',
  isAuthenticated,
  hasRole('admin'),
  [
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
  ],
  logSensitiveOperation('admin_security_events_access'),
  async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 50;
      const events = await auditService.getSecurityEvents(limit);

      res.json({
        events
      });
    } catch (error) {
      logger.error('Admin get security events error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get security events'
      });
    }
  }
);

/**
 * @route GET /api/admin/system-health
 * @desc Get system health information
 * @access Private (Admin)
 */
router.get('/system-health',
  isAuthenticated,
  hasRole('admin'),
  async (req, res) => {
    try {
      // Get database health
      const dbHealth = await getDatabaseHealth();
      
      // Get authentication status
      const { getAuthStatus } = require('../auth/passport');
      const authStatus = getAuthStatus();
      
      // Get email service status
      const emailStatus = await emailService.testConnection();
      
      // Get system metrics
      const systemMetrics = {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        version: process.version,
        platform: process.platform,
        environment: process.env.NODE_ENV || 'development',
        pid: process.pid
      };

      res.json({
        health: {
          database: dbHealth,
          authentication: authStatus,
          email: emailStatus,
          system: systemMetrics,
          timestamp: new Date().toISOString()
        }
      });
    } catch (error) {
      logger.error('Admin get system health error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get system health'
      });
    }
  }
);

/**
 * @route POST /api/admin/test-email
 * @desc Test email configuration
 * @access Private (Admin)
 */
router.post('/test-email',
  isAuthenticated,
  hasRole('admin'),
  [
    body('email').isEmail().withMessage('Valid email is required')
  ],
  logSensitiveOperation('admin_test_email'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Valid email is required'
        });
      }

      const { email } = req.body;

      // Send test email
      const result = await emailService.sendEmail(
        email,
        'AuthX Test Email',
        '<h1>Test Email</h1><p>This is a test email from AuthX. If you received this, email configuration is working correctly.</p>',
        'Test Email - This is a test email from AuthX. If you received this, email configuration is working correctly.'
      );

      // Log test email
      await auditService.log('admin_test_email_sent', {
        adminId: req.user._id,
        testEmail: email,
        success: result.success,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        message: result.success ? 'Test email sent successfully' : 'Failed to send test email',
        result
      });
    } catch (error) {
      logger.error('Admin test email error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to send test email'
      });
    }
  }
);

/**
 * @route GET /api/admin/roles
 * @desc Get all roles
 * @access Private (Admin)
 */
router.get('/roles',
  isAuthenticated,
  hasRole('admin'),
  async (req, res) => {
    try {
      const Role = require('../models/Role');
      const roles = await Role.find({ status: 'active' }).sort({ level: 1 });

      res.json({
        roles: roles.map(role => ({
          id: role._id,
          name: role.name,
          displayName: role.displayName,
          description: role.description,
          permissions: role.permissions,
          level: role.level,
          isSystem: role.isSystem,
          type: role.type,
          createdAt: role.createdAt
        }))
      });
    } catch (error) {
      logger.error('Admin get roles error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get roles'
      });
    }
  }
);

/**
 * @route GET /api/admin/export/users
 * @desc Export users data
 * @access Private (Admin)
 */
router.get('/export/users',
  isAuthenticated,
  hasRole('admin'),
  [
    query('format').optional().isIn(['json', 'csv']).withMessage('Format must be json or csv')
  ],
  logSensitiveOperation('admin_export_users'),
  async (req, res) => {
    try {
      const format = req.query.format || 'json';
      
      // Get all users (be careful with large datasets)
      const result = await userService.getUsers({ limit: 10000 });
      
      if (format === 'csv') {
        // Convert to CSV
        const csvHeaders = ['ID', 'Email', 'Username', 'Status', 'Email Verified', 'Created At', 'Last Login'];
        const csvRows = [csvHeaders.join(',')];
        
        result.users.forEach(user => {
          const row = [
            user._id,
            user.email,
            user.username || '',
            user.status,
            user.emailVerified,
            user.createdAt,
            user.lastLogin || ''
          ];
          csvRows.push(row.join(','));
        });
        
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=users.csv');
        res.send(csvRows.join('\n'));
      } else {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=users.json');
        res.json(result.users);
      }

      // Log export
      await auditService.log('admin_users_exported', {
        adminId: req.user._id,
        format,
        userCount: result.users.length,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
    } catch (error) {
      logger.error('Admin export users error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to export users'
      });
    }
  }
);

module.exports = router;

