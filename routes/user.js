const express = require('express');
const passport = require('passport');
const { asyncHandler } = require('../middleware/errorHandler');
const userService = require('../services/userService');
const { logger } = require('../utils/logger');

const router = express.Router();

/**
 * User Management Routes
 * Provides endpoints for user profile and account management
 */

// Middleware to ensure user is authenticated
const requireAuth = passport.authenticate(['jwt', 'session'], { session: false });

/**
 * GET /user/profile
 * Get user profile
 */
router.get('/profile', requireAuth, asyncHandler(async (req, res) => {
  const user = await userService.findById(req.user._id || req.user.id);
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  res.json({
    success: true,
    user: {
      id: user._id,
      email: user.email,
      username: user.username,
      profile: user.profile,
      emailVerified: user.emailVerified,
      status: user.status,
      authMethods: user.authMethods,
      mfa: {
        enabled: user.mfa.enabled,
        methods: user.mfa.methods
      },
      preferences: user.preferences,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    }
  });
}));

/**
 * PUT /user/profile
 * Update user profile
 */
router.put('/profile', requireAuth, asyncHandler(async (req, res) => {
  const userId = req.user._id || req.user.id;
  const allowedFields = [
    'profile.firstName',
    'profile.lastName',
    'profile.displayName',
    'profile.bio',
    'profile.phone',
    'profile.timezone',
    'profile.locale',
    'username',
    'preferences'
  ];

  // Filter update data to only allowed fields
  const updateData = {};
  Object.keys(req.body).forEach(key => {
    if (allowedFields.includes(key)) {
      updateData[key] = req.body[key];
    } else if (key.startsWith('profile.') && allowedFields.some(field => field.startsWith('profile.'))) {
      updateData[key] = req.body[key];
    }
  });

  if (Object.keys(updateData).length === 0) {
    return res.status(400).json({
      success: false,
      error: 'No valid fields to update'
    });
  }

  try {
    const updatedUser = await userService.update(userId, updateData, {
      updatedBy: userId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      user: {
        id: updatedUser._id,
        email: updatedUser.email,
        username: updatedUser.username,
        profile: updatedUser.profile,
        preferences: updatedUser.preferences,
        updatedAt: updatedUser.updatedAt
      },
      message: 'Profile updated successfully'
    });
  } catch (error) {
    logger.error('Profile update error:', error);
    res.status(400).json({
      success: false,
      error: error.message || 'Profile update failed'
    });
  }
}));

/**
 * GET /user/permissions
 * Get user permissions
 */
router.get('/permissions', requireAuth, asyncHandler(async (req, res) => {
  const userId = req.user._id || req.user.id;
  const permissions = await userService.getPermissions(userId);

  res.json({
    success: true,
    permissions
  });
}));

/**
 * GET /user/roles
 * Get user roles
 */
router.get('/roles', requireAuth, asyncHandler(async (req, res) => {
  const user = await userService.findById(req.user._id || req.user.id);
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  res.json({
    success: true,
    roles: user.roles
  });
}));

/**
 * GET /user/security
 * Get user security information
 */
router.get('/security', requireAuth, asyncHandler(async (req, res) => {
  const user = await userService.findById(req.user._id || req.user.id);
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  res.json({
    success: true,
    security: {
      lastPasswordChange: user.security.lastPasswordChange,
      lastLogin: user.security.lastLogin,
      lastLoginIP: user.security.lastLoginIP,
      loginHistory: user.security.loginHistory.slice(-5), // Last 5 logins
      mfa: {
        enabled: user.mfa.enabled,
        methods: user.mfa.methods,
        backupCodesCount: user.mfa.backupCodes ? user.mfa.backupCodes.filter(c => !c.used).length : 0
      },
      authMethods: user.authMethods
    }
  });
}));

/**
 * POST /user/deactivate
 * Deactivate user account
 */
router.post('/deactivate', requireAuth, asyncHandler(async (req, res) => {
  const userId = req.user._id || req.user.id;
  const { password, reason } = req.body;

  // Verify password for security
  const user = await userService.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  if (user.authMethods.includes('local')) {
    if (!password) {
      return res.status(400).json({
        success: false,
        error: 'Password required for account deactivation'
      });
    }

    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: 'Invalid password'
      });
    }
  }

  try {
    await userService.update(userId, {
      status: 'inactive',
      'metadata.deactivationReason': reason || 'User requested',
      'metadata.deactivatedAt': new Date()
    }, {
      updatedBy: userId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'Account deactivated successfully'
    });
  } catch (error) {
    logger.error('Account deactivation error:', error);
    res.status(500).json({
      success: false,
      error: 'Account deactivation failed'
    });
  }
}));

/**
 * DELETE /user/account
 * Delete user account (soft delete)
 */
router.delete('/account', requireAuth, asyncHandler(async (req, res) => {
  const userId = req.user._id || req.user.id;
  const { password, confirmation } = req.body;

  if (confirmation !== 'DELETE') {
    return res.status(400).json({
      success: false,
      error: 'Account deletion must be confirmed with "DELETE"'
    });
  }

  // Verify password for security
  const user = await userService.findById(userId);
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  if (user.authMethods.includes('local')) {
    if (!password) {
      return res.status(400).json({
        success: false,
        error: 'Password required for account deletion'
      });
    }

    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: 'Invalid password'
      });
    }
  }

  try {
    await userService.delete(userId, {
      softDelete: true,
      deletedBy: userId,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    logger.error('Account deletion error:', error);
    res.status(500).json({
      success: false,
      error: 'Account deletion failed'
    });
  }
}));

/**
 * GET /user/activity
 * Get user activity log
 */
router.get('/activity', requireAuth, asyncHandler(async (req, res) => {
  const user = await userService.findById(req.user._id || req.user.id);
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  const { page = 1, limit = 10 } = req.query;
  const skip = (page - 1) * limit;

  // Get recent login history
  const loginHistory = user.security.loginHistory
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(skip, skip + parseInt(limit));

  res.json({
    success: true,
    activity: {
      loginHistory,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: user.security.loginHistory.length
      }
    }
  });
}));

/**
 * POST /user/export
 * Export user data (GDPR compliance)
 */
router.post('/export', requireAuth, asyncHandler(async (req, res) => {
  const userId = req.user._id || req.user.id;
  const user = await userService.findById(userId);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }

  // Create exportable user data (excluding sensitive information)
  const exportData = {
    profile: user.profile,
    email: user.email,
    username: user.username,
    emailVerified: user.emailVerified,
    status: user.status,
    authMethods: user.authMethods,
    preferences: user.preferences,
    roles: user.roles,
    permissions: await userService.getPermissions(userId),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    security: {
      lastLogin: user.security.lastLogin,
      lastLoginIP: user.security.lastLoginIP,
      loginHistory: user.security.loginHistory
    },
    exportedAt: new Date().toISOString()
  };

  res.json({
    success: true,
    data: exportData,
    message: 'User data exported successfully'
  });
}));

module.exports = router;

