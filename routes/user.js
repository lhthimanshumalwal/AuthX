const express = require('express');
const { body, param, query, validationResult } = require('express-validator');
const userService = require('../services/userService');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');
const { 
  isAuthenticated, 
  hasRole, 
  hasPermission, 
  isOwnerOrAdmin,
  requireEmailVerification 
} = require('../middleware/authMiddleware');
const { logDataAccess } = require('../middleware/auditLogger');

const router = express.Router();

/**
 * @route GET /api/users/profile
 * @desc Get current user's profile
 * @access Private
 */
router.get('/profile', 
  isAuthenticated,
  logDataAccess('user_profile', 'read'),
  async (req, res) => {
    try {
      res.json({
        user: {
          id: req.user._id,
          email: req.user.email,
          username: req.user.username,
          profile: req.user.profile,
          roles: req.user.roles.map(r => r.name || r),
          permissions: req.user.permissions,
          status: req.user.status,
          emailVerified: req.user.emailVerified,
          twoFactorEnabled: req.user.twoFactorAuth?.enabled || false,
          lastLogin: req.user.lastLogin,
          createdAt: req.user.createdAt,
          updatedAt: req.user.updatedAt,
          authProviders: req.user.authProviders,
          metadata: req.user.metadata
        }
      });
    } catch (error) {
      logger.error('Get profile error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get user profile'
      });
    }
  }
);

/**
 * @route PUT /api/users/profile
 * @desc Update current user's profile
 * @access Private
 */
router.put('/profile',
  isAuthenticated,
  requireEmailVerification,
  [
    body('profile.firstName').optional().trim().isLength({ min: 1, max: 50 }).withMessage('First name must be 1-50 characters'),
    body('profile.lastName').optional().trim().isLength({ min: 1, max: 50 }).withMessage('Last name must be 1-50 characters'),
    body('profile.displayName').optional().trim().isLength({ min: 1, max: 100 }).withMessage('Display name must be 1-100 characters'),
    body('profile.bio').optional().trim().isLength({ max: 500 }).withMessage('Bio must be less than 500 characters'),
    body('profile.website').optional().isURL().withMessage('Website must be a valid URL'),
    body('profile.location').optional().trim().isLength({ max: 100 }).withMessage('Location must be less than 100 characters'),
    body('profile.timezone').optional().trim().isLength({ max: 50 }).withMessage('Timezone must be less than 50 characters'),
    body('profile.language').optional().trim().isLength({ max: 10 }).withMessage('Language must be less than 10 characters')
  ],
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

      const { profile } = req.body;

      // Update user profile
      const updatedUser = await userService.updateUser(req.user._id, { profile }, req.user._id);

      res.json({
        message: 'Profile updated successfully',
        user: {
          id: updatedUser._id,
          email: updatedUser.email,
          username: updatedUser.username,
          profile: updatedUser.profile,
          updatedAt: updatedUser.updatedAt
        }
      });
    } catch (error) {
      logger.error('Update profile error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update profile'
      });
    }
  }
);

/**
 * @route POST /api/users/change-password
 * @desc Change user password
 * @access Private
 */
router.post('/change-password',
  isAuthenticated,
  requireEmailVerification,
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long')
  ],
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

      const { currentPassword, newPassword } = req.body;

      // Verify current password
      const isValidPassword = await req.user.comparePassword(currentPassword);
      if (!isValidPassword) {
        await auditService.log('password_change_failed', {
          userId: req.user._id,
          reason: 'invalid_current_password',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.status(400).json({
          error: 'Bad Request',
          message: 'Current password is incorrect'
        });
      }

      // Update password
      await userService.updateUser(req.user._id, { password: newPassword }, req.user._id);

      // Log password change
      await auditService.log('password_changed', {
        userId: req.user._id,
        email: req.user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        message: 'Password changed successfully'
      });
    } catch (error) {
      logger.error('Change password error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to change password'
      });
    }
  }
);

/**
 * @route GET /api/users/:id
 * @desc Get user by ID
 * @access Private (Admin or Owner)
 */
router.get('/:id',
  isAuthenticated,
  [
    param('id').isMongoId().withMessage('Invalid user ID')
  ],
  isOwnerOrAdmin('id'),
  logDataAccess('user_details', 'read'),
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

      res.json({
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          profile: user.profile,
          roles: user.roles.map(r => r.name || r),
          status: user.status,
          emailVerified: user.emailVerified,
          twoFactorEnabled: user.twoFactorAuth?.enabled || false,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
          authProviders: user.authProviders
        }
      });
    } catch (error) {
      logger.error('Get user error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get user'
      });
    }
  }
);

/**
 * @route GET /api/users
 * @desc Get users with pagination and filtering
 * @access Private (Admin)
 */
router.get('/',
  isAuthenticated,
  hasRole('admin'),
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('search').optional().trim().isLength({ max: 100 }).withMessage('Search term must be less than 100 characters'),
    query('status').optional().isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status'),
    query('role').optional().trim().isLength({ max: 50 }).withMessage('Role must be less than 50 characters'),
    query('sortBy').optional().isIn(['createdAt', 'updatedAt', 'lastLogin', 'email', 'status']).withMessage('Invalid sort field'),
    query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc')
  ],
  logDataAccess('users_list', 'read'),
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
          createdAt: user.createdAt,
          authProviders: user.authProviders
        })),
        pagination: result.pagination
      });
    } catch (error) {
      logger.error('Get users error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get users'
      });
    }
  }
);

/**
 * @route PUT /api/users/:id
 * @desc Update user (Admin only)
 * @access Private (Admin)
 */
router.put('/:id',
  isAuthenticated,
  hasRole('admin'),
  [
    param('id').isMongoId().withMessage('Invalid user ID'),
    body('profile').optional().isObject().withMessage('Profile must be an object'),
    body('status').optional().isIn(['active', 'inactive', 'suspended', 'pending']).withMessage('Invalid status'),
    body('emailVerified').optional().isBoolean().withMessage('Email verified must be a boolean')
  ],
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

      const { profile, status, emailVerified } = req.body;
      const updateData = {};

      if (profile) updateData.profile = profile;
      if (status) updateData.status = status;
      if (typeof emailVerified === 'boolean') updateData.emailVerified = emailVerified;

      const updatedUser = await userService.updateUser(req.params.id, updateData, req.user._id);

      if (!updatedUser) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'User not found'
        });
      }

      res.json({
        message: 'User updated successfully',
        user: {
          id: updatedUser._id,
          email: updatedUser.email,
          username: updatedUser.username,
          profile: updatedUser.profile,
          status: updatedUser.status,
          emailVerified: updatedUser.emailVerified,
          updatedAt: updatedUser.updatedAt
        }
      });
    } catch (error) {
      logger.error('Update user error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update user'
      });
    }
  }
);

/**
 * @route DELETE /api/users/:id
 * @desc Delete user (Admin only)
 * @access Private (Admin)
 */
router.delete('/:id',
  isAuthenticated,
  hasRole('admin'),
  [
    param('id').isMongoId().withMessage('Invalid user ID')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid user ID'
        });
      }

      // Prevent admin from deleting themselves
      if (req.params.id === req.user._id.toString()) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Cannot delete your own account'
        });
      }

      const deleted = await userService.deleteUser(req.params.id, req.user._id);

      if (!deleted) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'User not found'
        });
      }

      res.json({
        message: 'User deleted successfully'
      });
    } catch (error) {
      logger.error('Delete user error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to delete user'
      });
    }
  }
);

/**
 * @route POST /api/users/:id/assign-role
 * @desc Assign role to user
 * @access Private (Admin)
 */
router.post('/:id/assign-role',
  isAuthenticated,
  hasRole('admin'),
  [
    param('id').isMongoId().withMessage('Invalid user ID'),
    body('role').notEmpty().trim().withMessage('Role is required')
  ],
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

      const { role } = req.body;

      const user = await userService.assignRole(req.params.id, role, req.user._id);

      if (!user) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'User or role not found'
        });
      }

      res.json({
        message: 'Role assigned successfully',
        user: {
          id: user._id,
          email: user.email,
          roles: user.roles.map(r => r.name || r)
        }
      });
    } catch (error) {
      logger.error('Assign role error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to assign role'
      });
    }
  }
);

/**
 * @route DELETE /api/users/:id/remove-role
 * @desc Remove role from user
 * @access Private (Admin)
 */
router.delete('/:id/remove-role',
  isAuthenticated,
  hasRole('admin'),
  [
    param('id').isMongoId().withMessage('Invalid user ID'),
    body('role').notEmpty().trim().withMessage('Role is required')
  ],
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

      const { role } = req.body;

      const user = await userService.removeRole(req.params.id, role, req.user._id);

      if (!user) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'User or role not found'
        });
      }

      res.json({
        message: 'Role removed successfully',
        user: {
          id: user._id,
          email: user.email,
          roles: user.roles.map(r => r.name || r)
        }
      });
    } catch (error) {
      logger.error('Remove role error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to remove role'
      });
    }
  }
);

/**
 * @route GET /api/users/stats
 * @desc Get user statistics
 * @access Private (Admin)
 */
router.get('/stats',
  isAuthenticated,
  hasRole('admin'),
  logDataAccess('user_stats', 'read'),
  async (req, res) => {
    try {
      const stats = await userService.getUserStats();

      res.json({
        stats
      });
    } catch (error) {
      logger.error('Get user stats error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get user statistics'
      });
    }
  }
);

module.exports = router;

