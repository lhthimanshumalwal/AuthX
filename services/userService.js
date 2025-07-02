const User = require('../models/User');
const Role = require('../models/Role');
const Permission = require('../models/Permission');
const { logger, audit } = require('../utils/logger');
const config = require('../config/config');
const crypto = require('crypto');

/**
 * User Service - Handles all user-related operations
 * Provides a centralized service layer for user management
 */
class UserService {
  /**
   * Create a new user
   * @param {Object} userData - User data
   * @param {Object} options - Creation options
   * @returns {Promise<User>} Created user
   */
  async create(userData, options = {}) {
    try {
      // Validate required fields
      if (!userData.email) {
        throw new Error('Email is required');
      }

      // Check if user already exists
      const existingUser = await User.findOne({ email: userData.email.toLowerCase() });
      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Check username uniqueness if provided
      if (userData.username) {
        const existingUsername = await User.findOne({ username: userData.username });
        if (existingUsername) {
          throw new Error('Username is already taken');
        }
      }

      // Set default values
      const user = new User({
        ...userData,
        email: userData.email.toLowerCase(),
        status: options.autoActivate ? 'active' : 'pending',
        emailVerified: options.skipEmailVerification || false,
        metadata: {
          source: options.source || 'registration',
          ...userData.metadata
        }
      });

      // Assign default role if not specified
      if (!userData.roles || userData.roles.length === 0) {
        const defaultRole = await Role.findDefault();
        if (defaultRole) {
          user.roles = [defaultRole._id];
        }
      }

      // Generate email verification token if needed
      if (!user.emailVerified && config.features.enableEmailVerification) {
        user.emailVerificationToken = crypto.randomBytes(32).toString('hex');
        user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      }

      await user.save();

      // Log user creation
      audit.userRegistration({
        userId: user._id,
        email: user.email,
        source: user.metadata.source,
        ip: options.ip,
        userAgent: options.userAgent
      });

      logger.info('User created successfully', {
        userId: user._id,
        email: user.email,
        source: user.metadata.source
      });

      return user;
    } catch (error) {
      logger.error('Failed to create user:', error);
      throw error;
    }
  }

  /**
   * Find user by ID
   * @param {string} id - User ID
   * @returns {Promise<User|null>} User or null
   */
  async findById(id) {
    try {
      return await User.findById(id).populate('roles');
    } catch (error) {
      logger.error('Failed to find user by ID:', error);
      return null;
    }
  }

  /**
   * Find user by email
   * @param {string} email - User email
   * @returns {Promise<User|null>} User or null
   */
  async findByEmail(email) {
    try {
      return await User.findOne({ email: email.toLowerCase() }).populate('roles');
    } catch (error) {
      logger.error('Failed to find user by email:', error);
      return null;
    }
  }

  /**
   * Find user by email or username
   * @param {string} identifier - Email or username
   * @returns {Promise<User|null>} User or null
   */
  async findByEmailOrUsername(identifier) {
    try {
      return await User.findByEmailOrUsername(identifier).populate('roles');
    } catch (error) {
      logger.error('Failed to find user by email or username:', error);
      return null;
    }
  }

  /**
   * Find user by provider
   * @param {string} provider - Provider name (google, github, etc.)
   * @param {string} providerId - Provider user ID
   * @returns {Promise<User|null>} User or null
   */
  async findByProvider(provider, providerId) {
    try {
      return await User.findByProvider(provider, providerId).populate('roles');
    } catch (error) {
      logger.error('Failed to find user by provider:', error);
      return null;
    }
  }

  /**
   * Update user
   * @param {string} id - User ID
   * @param {Object} updateData - Update data
   * @param {Object} options - Update options
   * @returns {Promise<User>} Updated user
   */
  async update(id, updateData, options = {}) {
    try {
      const user = await User.findById(id);
      if (!user) {
        throw new Error('User not found');
      }

      // Handle email change
      if (updateData.email && updateData.email !== user.email) {
        const existingUser = await User.findOne({ email: updateData.email.toLowerCase() });
        if (existingUser && !existingUser._id.equals(user._id)) {
          throw new Error('Email is already in use');
        }
        
        updateData.email = updateData.email.toLowerCase();
        updateData.emailVerified = false;
        
        if (config.features.enableEmailVerification) {
          updateData.emailVerificationToken = crypto.randomBytes(32).toString('hex');
          updateData.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
        }
      }

      // Handle username change
      if (updateData.username && updateData.username !== user.username) {
        const existingUser = await User.findOne({ username: updateData.username });
        if (existingUser && !existingUser._id.equals(user._id)) {
          throw new Error('Username is already taken');
        }
      }

      // Update user
      Object.assign(user, updateData);
      await user.save();

      logger.info('User updated successfully', {
        userId: user._id,
        updatedBy: options.updatedBy,
        fields: Object.keys(updateData)
      });

      return user;
    } catch (error) {
      logger.error('Failed to update user:', error);
      throw error;
    }
  }

  /**
   * Delete user
   * @param {string} id - User ID
   * @param {Object} options - Delete options
   * @returns {Promise<boolean>} Success status
   */
  async delete(id, options = {}) {
    try {
      const user = await User.findById(id);
      if (!user) {
        throw new Error('User not found');
      }

      if (options.softDelete) {
        user.status = 'inactive';
        user.email = `deleted_${Date.now()}_${user.email}`;
        await user.save();
      } else {
        await User.findByIdAndDelete(id);
      }

      logger.info('User deleted successfully', {
        userId: id,
        deletedBy: options.deletedBy,
        softDelete: options.softDelete
      });

      return true;
    } catch (error) {
      logger.error('Failed to delete user:', error);
      throw error;
    }
  }

  /**
   * Authenticate user with password
   * @param {string} identifier - Email or username
   * @param {string} password - Password
   * @param {Object} options - Authentication options
   * @returns {Promise<Object>} Authentication result
   */
  async authenticate(identifier, password, options = {}) {
    try {
      const user = await this.findByEmailOrUsername(identifier);
      if (!user) {
        await this.recordFailedLogin(null, options.ip, options.userAgent, 'local');
        return { success: false, error: 'Invalid credentials' };
      }

      // Check if account is locked
      if (user.isLocked) {
        await user.recordFailedLogin(options.ip, options.userAgent, 'local');
        audit.authFailure({
          userId: user._id,
          email: user.email,
          reason: 'account_locked',
          ip: options.ip,
          userAgent: options.userAgent
        });
        return { success: false, error: 'Account is temporarily locked' };
      }

      // Check if account is active
      if (user.status !== 'active') {
        await user.recordFailedLogin(options.ip, options.userAgent, 'local');
        audit.authFailure({
          userId: user._id,
          email: user.email,
          reason: 'account_inactive',
          ip: options.ip,
          userAgent: options.userAgent
        });
        return { success: false, error: 'Account is not active' };
      }

      // Verify password
      const isValidPassword = await user.comparePassword(password);
      if (!isValidPassword) {
        await user.incLoginAttempts();
        await user.recordFailedLogin(options.ip, options.userAgent, 'local');
        audit.authFailure({
          userId: user._id,
          email: user.email,
          reason: 'invalid_password',
          ip: options.ip,
          userAgent: options.userAgent
        });
        return { success: false, error: 'Invalid credentials' };
      }

      // Reset login attempts on successful authentication
      if (user.security.loginAttempts > 0) {
        await user.resetLoginAttempts();
      }

      // Record successful login
      await user.recordLogin(options.ip, options.userAgent, 'local');
      
      audit.authSuccess({
        userId: user._id,
        email: user.email,
        strategy: 'local',
        ip: options.ip,
        userAgent: options.userAgent
      });

      return { success: true, user };
    } catch (error) {
      logger.error('Authentication failed:', error);
      return { success: false, error: 'Authentication failed' };
    }
  }

  /**
   * Change user password
   * @param {string} userId - User ID
   * @param {string} currentPassword - Current password
   * @param {string} newPassword - New password
   * @param {Object} options - Options
   * @returns {Promise<boolean>} Success status
   */
  async changePassword(userId, currentPassword, newPassword, options = {}) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Verify current password
      if (currentPassword) {
        const isValidPassword = await user.comparePassword(currentPassword);
        if (!isValidPassword) {
          throw new Error('Current password is incorrect');
        }
      }

      // Check if new password was used recently
      const wasRecentlyUsed = await user.isPasswordRecentlyUsed(newPassword);
      if (wasRecentlyUsed) {
        throw new Error('Cannot reuse a recent password');
      }

      // Validate password strength
      this.validatePasswordStrength(newPassword);

      // Update password
      user.password = newPassword;
      await user.save();

      audit.passwordChange({
        userId: user._id,
        email: user.email,
        changedBy: options.changedBy || userId,
        ip: options.ip,
        userAgent: options.userAgent
      });

      logger.info('Password changed successfully', {
        userId: user._id,
        changedBy: options.changedBy || userId
      });

      return true;
    } catch (error) {
      logger.error('Failed to change password:', error);
      throw error;
    }
  }

  /**
   * Reset password
   * @param {string} token - Reset token
   * @param {string} newPassword - New password
   * @returns {Promise<boolean>} Success status
   */
  async resetPassword(token, newPassword) {
    try {
      const user = await User.findOne({
        passwordResetToken: token,
        passwordResetExpires: { $gt: Date.now() }
      });

      if (!user) {
        throw new Error('Invalid or expired reset token');
      }

      // Validate password strength
      this.validatePasswordStrength(newPassword);

      // Check if new password was used recently
      const wasRecentlyUsed = await user.isPasswordRecentlyUsed(newPassword);
      if (wasRecentlyUsed) {
        throw new Error('Cannot reuse a recent password');
      }

      // Update password and clear reset token
      user.password = newPassword;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      audit.passwordChange({
        userId: user._id,
        email: user.email,
        method: 'reset',
        ip: null,
        userAgent: null
      });

      logger.info('Password reset successfully', {
        userId: user._id,
        email: user.email
      });

      return true;
    } catch (error) {
      logger.error('Failed to reset password:', error);
      throw error;
    }
  }

  /**
   * Verify email
   * @param {string} token - Verification token
   * @returns {Promise<boolean>} Success status
   */
  async verifyEmail(token) {
    try {
      const user = await User.findOne({
        emailVerificationToken: token,
        emailVerificationExpires: { $gt: Date.now() }
      });

      if (!user) {
        throw new Error('Invalid or expired verification token');
      }

      user.emailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      
      if (user.status === 'pending') {
        user.status = 'active';
      }

      await user.save();

      logger.info('Email verified successfully', {
        userId: user._id,
        email: user.email
      });

      return true;
    } catch (error) {
      logger.error('Failed to verify email:', error);
      throw error;
    }
  }

  /**
   * Add role to user
   * @param {string} userId - User ID
   * @param {string} roleId - Role ID
   * @param {Object} options - Options
   * @returns {Promise<boolean>} Success status
   */
  async addRole(userId, roleId, options = {}) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      const role = await Role.findById(roleId);
      if (!role) {
        throw new Error('Role not found');
      }

      if (!user.roles.includes(roleId)) {
        user.roles.push(roleId);
        await user.save();

        audit.roleChange({
          userId: user._id,
          email: user.email,
          action: 'add',
          roleId: role._id,
          roleName: role.name,
          changedBy: options.changedBy,
          ip: options.ip,
          userAgent: options.userAgent
        });

        logger.info('Role added to user', {
          userId: user._id,
          roleId: role._id,
          roleName: role.name,
          changedBy: options.changedBy
        });
      }

      return true;
    } catch (error) {
      logger.error('Failed to add role to user:', error);
      throw error;
    }
  }

  /**
   * Remove role from user
   * @param {string} userId - User ID
   * @param {string} roleId - Role ID
   * @param {Object} options - Options
   * @returns {Promise<boolean>} Success status
   */
  async removeRole(userId, roleId, options = {}) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      const role = await Role.findById(roleId);
      if (!role) {
        throw new Error('Role not found');
      }

      user.roles = user.roles.filter(r => !r.equals(roleId));
      await user.save();

      audit.roleChange({
        userId: user._id,
        email: user.email,
        action: 'remove',
        roleId: role._id,
        roleName: role.name,
        changedBy: options.changedBy,
        ip: options.ip,
        userAgent: options.userAgent
      });

      logger.info('Role removed from user', {
        userId: user._id,
        roleId: role._id,
        roleName: role.name,
        changedBy: options.changedBy
      });

      return true;
    } catch (error) {
      logger.error('Failed to remove role from user:', error);
      throw error;
    }
  }

  /**
   * Check if user has permission
   * @param {string} userId - User ID
   * @param {string} permission - Permission string
   * @param {Object} context - Permission context
   * @returns {Promise<boolean>} Has permission
   */
  async hasPermission(userId, permission, context = {}) {
    try {
      const user = await User.findById(userId).populate({
        path: 'roles',
        populate: {
          path: 'permissions'
        }
      });

      if (!user) {
        return false;
      }

      // Check direct permissions
      if (user.permissions.includes(permission) || user.permissions.includes('*')) {
        return true;
      }

      // Check role permissions
      for (const role of user.roles) {
        const rolePermissions = await role.getAllPermissions();
        if (rolePermissions.includes(permission) || rolePermissions.includes('*')) {
          return true;
        }
      }

      return false;
    } catch (error) {
      logger.error('Failed to check user permission:', error);
      return false;
    }
  }

  /**
   * Get user permissions
   * @param {string} userId - User ID
   * @returns {Promise<Array>} User permissions
   */
  async getPermissions(userId) {
    try {
      const user = await User.findById(userId).populate({
        path: 'roles',
        populate: {
          path: 'permissions'
        }
      });

      if (!user) {
        return [];
      }

      const permissions = new Set(user.permissions);

      // Add role permissions
      for (const role of user.roles) {
        const rolePermissions = await role.getAllPermissions();
        rolePermissions.forEach(permission => permissions.add(permission));
      }

      return Array.from(permissions);
    } catch (error) {
      logger.error('Failed to get user permissions:', error);
      return [];
    }
  }

  /**
   * Record failed login attempt
   * @param {string|null} userId - User ID (null if user not found)
   * @param {string} ip - IP address
   * @param {string} userAgent - User agent
   * @param {string} strategy - Authentication strategy
   */
  async recordFailedLogin(userId, ip, userAgent, strategy) {
    audit.authFailure({
      userId,
      reason: 'invalid_credentials',
      strategy,
      ip,
      userAgent
    });
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @throws {Error} If password is weak
   */
  validatePasswordStrength(password) {
    const { security } = config;
    
    if (password.length < security.passwordMinLength) {
      throw new Error(`Password must be at least ${security.passwordMinLength} characters long`);
    }

    if (security.passwordRequireUppercase && !/[A-Z]/.test(password)) {
      throw new Error('Password must contain at least one uppercase letter');
    }

    if (security.passwordRequireLowercase && !/[a-z]/.test(password)) {
      throw new Error('Password must contain at least one lowercase letter');
    }

    if (security.passwordRequireNumbers && !/\d/.test(password)) {
      throw new Error('Password must contain at least one number');
    }

    if (security.passwordRequireSymbols && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      throw new Error('Password must contain at least one special character');
    }
  }

  /**
   * Get user statistics
   * @returns {Promise<Object>} User statistics
   */
  async getStats() {
    try {
      const stats = await User.aggregate([
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            active: { $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } },
            pending: { $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } },
            suspended: { $sum: { $cond: [{ $eq: ['$status', 'suspended'] }, 1, 0] } },
            emailVerified: { $sum: { $cond: ['$emailVerified', 1, 0] } },
            mfaEnabled: { $sum: { $cond: ['$mfa.enabled', 1, 0] } }
          }
        }
      ]);

      return stats[0] || {
        total: 0,
        active: 0,
        pending: 0,
        suspended: 0,
        emailVerified: 0,
        mfaEnabled: 0
      };
    } catch (error) {
      logger.error('Failed to get user statistics:', error);
      return {};
    }
  }
}

module.exports = new UserService();

