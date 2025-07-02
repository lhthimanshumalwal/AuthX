const User = require('../models/User');
const Role = require('../models/Role');
const Session = require('../models/Session');
const config = require('../config/config');
const logger = require('../utils/logger');
const emailService = require('./emailService');
const auditService = require('./auditService');

class UserService {
  /**
   * Create a new user
   */
  async createUser(userData, createdBy = null) {
    try {
      // Check if user already exists
      const existingUser = await User.findByEmailOrUsername(userData.email);
      if (existingUser) {
        throw new Error('User already exists with this email or username');
      }

      // Validate password if provided
      if (userData.password) {
        this.validatePassword(userData.password);
      }

      // Create user
      const user = new User({
        ...userData,
        createdBy: createdBy,
        status: config.security.requireEmailVerification ? 'pending' : 'active'
      });

      // Assign default role
      const defaultRole = await Role.findOne({ name: 'user' });
      if (defaultRole) {
        user.roles.push(defaultRole._id);
      }

      // Generate email verification token if required
      if (config.security.requireEmailVerification) {
        user.generateEmailVerificationToken();
      }

      await user.save();
      await user.populate('roles');

      // Send verification email if required
      if (config.security.requireEmailVerification) {
        await emailService.sendVerificationEmail(user);
      }

      // Log user creation
      await auditService.log('user_created', {
        userId: user._id,
        email: user.email,
        createdBy: createdBy
      });

      logger.info(`User created: ${user.email}`);
      return user;
    } catch (error) {
      logger.error('Error creating user:', error);
      throw error;
    }
  }

  /**
   * Authenticate user with email/password
   */
  async authenticateUser(identifier, password, deviceInfo = {}) {
    try {
      const user = await User.findByEmailOrUsername(identifier).populate('roles');
      
      if (!user) {
        await auditService.log('login_failed', {
          identifier,
          reason: 'user_not_found',
          deviceInfo
        });
        throw new Error('Invalid credentials');
      }

      // Check if account is locked
      if (user.isLocked) {
        await auditService.log('login_failed', {
          userId: user._id,
          reason: 'account_locked',
          deviceInfo
        });
        throw new Error('Account is temporarily locked due to too many failed login attempts');
      }

      // Check if account is active
      if (user.status !== 'active') {
        await auditService.log('login_failed', {
          userId: user._id,
          reason: 'account_inactive',
          status: user.status,
          deviceInfo
        });
        throw new Error('Account is not active');
      }

      // Verify password
      const isValidPassword = await user.comparePassword(password);
      if (!isValidPassword) {
        await user.incLoginAttempts();
        await auditService.log('login_failed', {
          userId: user._id,
          reason: 'invalid_password',
          deviceInfo
        });
        throw new Error('Invalid credentials');
      }

      // Reset login attempts on successful login
      if (user.loginAttempts > 0) {
        await user.resetLoginAttempts();
      }

      // Update last login
      user.lastLogin = new Date();
      user.lastLoginIP = deviceInfo.ip;
      await user.save();

      // Log successful login
      await auditService.log('login_success', {
        userId: user._id,
        email: user.email,
        deviceInfo
      });

      logger.info(`User authenticated: ${user.email}`);
      return user;
    } catch (error) {
      logger.error('Error authenticating user:', error);
      throw error;
    }
  }

  /**
   * Create or update user from OAuth provider
   */
  async createOrUpdateOAuthUser(provider, profile, accessToken) {
    try {
      let user = await User.findByOAuthProvider(provider, profile.id);
      
      if (user) {
        // Update existing user
        user.oauthProviders[provider] = {
          id: profile.id,
          email: profile.emails?.[0]?.value,
          username: profile.username,
          verified: profile.emails?.[0]?.verified || false
        };
        
        // Update profile information if not set
        if (!user.profile.displayName && profile.displayName) {
          user.profile.displayName = profile.displayName;
        }
        if (!user.profile.avatar && profile.photos?.[0]?.value) {
          user.profile.avatar = profile.photos[0].value;
        }
        
        user.lastLogin = new Date();
        await user.save();
        
        logger.info(`OAuth user updated: ${user.email} via ${provider}`);
      } else {
        // Check if user exists with same email
        const email = profile.emails?.[0]?.value;
        if (email) {
          user = await User.findOne({ email: email.toLowerCase() });
          if (user) {
            // Link OAuth account to existing user
            user.oauthProviders[provider] = {
              id: profile.id,
              email: email,
              username: profile.username,
              verified: profile.emails?.[0]?.verified || false
            };
            
            if (!user.authProviders.includes(provider)) {
              user.authProviders.push(provider);
            }
            
            await user.save();
            logger.info(`OAuth account linked: ${user.email} via ${provider}`);
          }
        }
        
        if (!user) {
          // Create new user
          user = new User({
            email: email?.toLowerCase(),
            username: profile.username,
            profile: {
              displayName: profile.displayName,
              firstName: profile.name?.givenName,
              lastName: profile.name?.familyName,
              avatar: profile.photos?.[0]?.value
            },
            authProviders: [provider],
            oauthProviders: {
              [provider]: {
                id: profile.id,
                email: email,
                username: profile.username,
                verified: profile.emails?.[0]?.verified || false
              }
            },
            status: 'active',
            emailVerified: profile.emails?.[0]?.verified || false,
            lastLogin: new Date()
          });

          // Assign default role
          const defaultRole = await Role.findOne({ name: 'user' });
          if (defaultRole) {
            user.roles.push(defaultRole._id);
          }

          await user.save();
          
          // Log user creation
          await auditService.log('oauth_user_created', {
            userId: user._id,
            email: user.email,
            provider: provider
          });
          
          logger.info(`OAuth user created: ${user.email} via ${provider}`);
        }
      }

      await user.populate('roles');
      return user;
    } catch (error) {
      logger.error(`Error creating/updating OAuth user from ${provider}:`, error);
      throw error;
    }
  }

  /**
   * Get user by ID
   */
  async getUserById(userId) {
    try {
      const user = await User.findById(userId).populate('roles');
      return user;
    } catch (error) {
      logger.error('Error getting user by ID:', error);
      throw error;
    }
  }

  /**
   * Get user by email
   */
  async getUserByEmail(email) {
    try {
      const user = await User.findOne({ email: email.toLowerCase() }).populate('roles');
      return user;
    } catch (error) {
      logger.error('Error getting user by email:', error);
      throw error;
    }
  }

  /**
   * Update user profile
   */
  async updateUser(userId, updateData, updatedBy = null) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Validate password if being updated
      if (updateData.password) {
        this.validatePassword(updateData.password);
      }

      // Update user
      Object.assign(user, updateData);
      user.updatedBy = updatedBy;
      await user.save();

      // Log user update
      await auditService.log('user_updated', {
        userId: user._id,
        updatedFields: Object.keys(updateData),
        updatedBy: updatedBy
      });

      logger.info(`User updated: ${user.email}`);
      return user;
    } catch (error) {
      logger.error('Error updating user:', error);
      throw error;
    }
  }

  /**
   * Delete user
   */
  async deleteUser(userId, deletedBy = null) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      // Revoke all sessions
      await Session.revokeAllForUser(userId, 'user_deleted');

      // Delete user
      await User.findByIdAndDelete(userId);

      // Log user deletion
      await auditService.log('user_deleted', {
        userId: userId,
        email: user.email,
        deletedBy: deletedBy
      });

      logger.info(`User deleted: ${user.email}`);
      return true;
    } catch (error) {
      logger.error('Error deleting user:', error);
      throw error;
    }
  }

  /**
   * Verify email
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
      user.status = 'active';
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();

      // Log email verification
      await auditService.log('email_verified', {
        userId: user._id,
        email: user.email
      });

      logger.info(`Email verified: ${user.email}`);
      return user;
    } catch (error) {
      logger.error('Error verifying email:', error);
      throw error;
    }
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(email) {
    try {
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        // Don't reveal if user exists
        return { message: 'If the email exists, a reset link has been sent' };
      }

      const token = user.generatePasswordResetToken();
      await user.save();

      // Send password reset email
      await emailService.sendPasswordResetEmail(user, token);

      // Log password reset request
      await auditService.log('password_reset_requested', {
        userId: user._id,
        email: user.email
      });

      logger.info(`Password reset requested: ${user.email}`);
      return { message: 'If the email exists, a reset link has been sent' };
    } catch (error) {
      logger.error('Error requesting password reset:', error);
      throw error;
    }
  }

  /**
   * Reset password
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

      // Validate new password
      this.validatePassword(newPassword);

      user.password = newPassword;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      // Revoke all existing sessions
      await Session.revokeAllForUser(user._id, 'password_reset');

      // Log password reset
      await auditService.log('password_reset', {
        userId: user._id,
        email: user.email
      });

      logger.info(`Password reset: ${user.email}`);
      return user;
    } catch (error) {
      logger.error('Error resetting password:', error);
      throw error;
    }
  }

  /**
   * Assign role to user
   */
  async assignRole(userId, roleName, assignedBy = null) {
    try {
      const user = await User.findById(userId);
      const role = await Role.findOne({ name: roleName });

      if (!user || !role) {
        throw new Error('User or role not found');
      }

      if (!user.roles.includes(role._id)) {
        user.roles.push(role._id);
        user.updatedBy = assignedBy;
        await user.save();

        // Log role assignment
        await auditService.log('role_assigned', {
          userId: user._id,
          roleId: role._id,
          roleName: roleName,
          assignedBy: assignedBy
        });

        logger.info(`Role assigned: ${roleName} to ${user.email}`);
      }

      return user;
    } catch (error) {
      logger.error('Error assigning role:', error);
      throw error;
    }
  }

  /**
   * Remove role from user
   */
  async removeRole(userId, roleName, removedBy = null) {
    try {
      const user = await User.findById(userId);
      const role = await Role.findOne({ name: roleName });

      if (!user || !role) {
        throw new Error('User or role not found');
      }

      user.roles = user.roles.filter(r => !r.equals(role._id));
      user.updatedBy = removedBy;
      await user.save();

      // Log role removal
      await auditService.log('role_removed', {
        userId: user._id,
        roleId: role._id,
        roleName: roleName,
        removedBy: removedBy
      });

      logger.info(`Role removed: ${roleName} from ${user.email}`);
      return user;
    } catch (error) {
      logger.error('Error removing role:', error);
      throw error;
    }
  }

  /**
   * Get users with pagination and filtering
   */
  async getUsers(options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        search = '',
        status = '',
        role = '',
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = options;

      const query = {};

      // Search filter
      if (search) {
        query.$or = [
          { email: { $regex: search, $options: 'i' } },
          { username: { $regex: search, $options: 'i' } },
          { 'profile.displayName': { $regex: search, $options: 'i' } },
          { 'profile.firstName': { $regex: search, $options: 'i' } },
          { 'profile.lastName': { $regex: search, $options: 'i' } }
        ];
      }

      // Status filter
      if (status) {
        query.status = status;
      }

      // Role filter
      if (role) {
        const roleDoc = await Role.findOne({ name: role });
        if (roleDoc) {
          query.roles = roleDoc._id;
        }
      }

      const sort = {};
      sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

      const users = await User.find(query)
        .populate('roles')
        .sort(sort)
        .limit(limit * 1)
        .skip((page - 1) * limit);

      const total = await User.countDocuments(query);

      return {
        users,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      logger.error('Error getting users:', error);
      throw error;
    }
  }

  /**
   * Validate password strength
   */
  validatePassword(password) {
    if (!password || password.length < config.security.passwordMinLength) {
      throw new Error(`Password must be at least ${config.security.passwordMinLength} characters long`);
    }

    // Add more password validation rules as needed
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
      throw new Error('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character');
    }

    return true;
  }

  /**
   * Get user statistics
   */
  async getUserStats() {
    try {
      const stats = await User.aggregate([
        {
          $group: {
            _id: null,
            totalUsers: { $sum: 1 },
            activeUsers: {
              $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
            },
            pendingUsers: {
              $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
            },
            suspendedUsers: {
              $sum: { $cond: [{ $eq: ['$status', 'suspended'] }, 1, 0] }
            },
            verifiedUsers: {
              $sum: { $cond: ['$emailVerified', 1, 0] }
            },
            usersWithTwoFA: {
              $sum: { $cond: ['$twoFactorAuth.enabled', 1, 0] }
            }
          }
        }
      ]);

      return stats[0] || {
        totalUsers: 0,
        activeUsers: 0,
        pendingUsers: 0,
        suspendedUsers: 0,
        verifiedUsers: 0,
        usersWithTwoFA: 0
      };
    } catch (error) {
      logger.error('Error getting user stats:', error);
      throw error;
    }
  }
}

module.exports = new UserService();

