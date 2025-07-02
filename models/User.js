const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const config = require('../config/config');

const userSchema = new mongoose.Schema({
  // Basic Information
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true
  },
  username: {
    type: String,
    unique: true,
    sparse: true,
    trim: true,
    index: true
  },
  password: {
    type: String,
    required: function() {
      return this.authProviders.length === 0 || this.authProviders.includes('local');
    }
  },
  
  // Profile Information
  profile: {
    firstName: { type: String, trim: true },
    lastName: { type: String, trim: true },
    displayName: { type: String, trim: true },
    avatar: { type: String },
    bio: { type: String, maxlength: 500 },
    website: { type: String },
    location: { type: String },
    timezone: { type: String, default: 'UTC' },
    language: { type: String, default: 'en' }
  },

  // Authentication Providers
  authProviders: [{
    type: String,
    enum: ['local', 'google', 'github', 'saml', 'ldap', 'magic-link'],
    default: 'local'
  }],

  // OAuth Provider Data
  oauthProviders: {
    google: {
      id: String,
      email: String,
      verified: Boolean
    },
    github: {
      id: String,
      username: String,
      email: String
    },
    saml: {
      nameId: String,
      sessionIndex: String,
      attributes: mongoose.Schema.Types.Mixed
    },
    ldap: {
      dn: String,
      uid: String,
      attributes: mongoose.Schema.Types.Mixed
    }
  },

  // Account Status
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended', 'pending'],
    default: 'pending'
  },
  
  // Email Verification
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,

  // Password Reset
  passwordResetToken: String,
  passwordResetExpires: Date,

  // Security
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  lastLogin: Date,
  lastLoginIP: String,
  
  // Two-Factor Authentication
  twoFactorAuth: {
    enabled: { type: Boolean, default: false },
    secret: String,
    backupCodes: [String],
    lastUsed: Date
  },

  // Roles and Permissions
  roles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],
  permissions: [String],

  // Session Management
  activeSessions: [{
    sessionId: String,
    deviceInfo: {
      userAgent: String,
      ip: String,
      location: String
    },
    createdAt: { type: Date, default: Date.now },
    lastActivity: { type: Date, default: Date.now }
  }],

  // Audit Trail
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },

  // Metadata
  metadata: mongoose.Schema.Types.Mixed,
  tags: [String]
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.passwordResetToken;
      delete ret.emailVerificationToken;
      delete ret.twoFactorAuth.secret;
      delete ret.twoFactorAuth.backupCodes;
      return ret;
    }
  }
});

// Indexes
userSchema.index({ email: 1, status: 1 });
userSchema.index({ 'oauthProviders.google.id': 1 });
userSchema.index({ 'oauthProviders.github.id': 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ lastLogin: -1 });

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  if (this.profile.firstName && this.profile.lastName) {
    return `${this.profile.firstName} ${this.profile.lastName}`;
  }
  return this.profile.displayName || this.username || this.email;
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) return next();
  
  try {
    // Hash password with configured rounds
    const salt = await bcrypt.genSalt(config.security.bcryptRounds);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

// Method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock account after max attempts
  if (this.loginAttempts + 1 >= config.security.maxLoginAttempts && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + config.security.lockoutTime };
  }
  
  return this.updateOne(updates);
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Method to add session
userSchema.methods.addSession = function(sessionId, deviceInfo) {
  this.activeSessions.push({
    sessionId,
    deviceInfo,
    createdAt: new Date(),
    lastActivity: new Date()
  });
  
  // Keep only last 10 sessions
  if (this.activeSessions.length > 10) {
    this.activeSessions = this.activeSessions.slice(-10);
  }
  
  return this.save();
};

// Method to remove session
userSchema.methods.removeSession = function(sessionId) {
  this.activeSessions = this.activeSessions.filter(
    session => session.sessionId !== sessionId
  );
  return this.save();
};

// Method to update last activity
userSchema.methods.updateLastActivity = function(sessionId) {
  const session = this.activeSessions.find(s => s.sessionId === sessionId);
  if (session) {
    session.lastActivity = new Date();
    return this.save();
  }
};

// Method to check if user has role
userSchema.methods.hasRole = function(roleName) {
  return this.populated('roles') 
    ? this.roles.some(role => role.name === roleName)
    : false;
};

// Method to check if user has permission
userSchema.methods.hasPermission = function(permission) {
  return this.permissions.includes(permission) ||
    (this.populated('roles') && 
     this.roles.some(role => role.permissions.includes(permission)));
};

// Method to generate email verification token
userSchema.methods.generateEmailVerificationToken = function() {
  const crypto = require('crypto');
  this.emailVerificationToken = crypto.randomBytes(32).toString('hex');
  this.emailVerificationExpires = new Date(Date.now() + config.security.emailVerificationExpiry);
  return this.emailVerificationToken;
};

// Method to generate password reset token
userSchema.methods.generatePasswordResetToken = function() {
  const crypto = require('crypto');
  this.passwordResetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetExpires = new Date(Date.now() + config.security.passwordResetExpiry);
  return this.passwordResetToken;
};

// Static method to find by email or username
userSchema.statics.findByEmailOrUsername = function(identifier) {
  return this.findOne({
    $or: [
      { email: identifier.toLowerCase() },
      { username: identifier }
    ]
  });
};

// Static method to find by OAuth provider
userSchema.statics.findByOAuthProvider = function(provider, id) {
  const query = {};
  query[`oauthProviders.${provider}.id`] = id;
  return this.findOne(query);
};

module.exports = mongoose.model('User', userSchema);

