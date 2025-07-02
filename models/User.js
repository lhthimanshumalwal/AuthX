const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const config = require('../config/config');

const userSchema = new mongoose.Schema({
  // Basic user information
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
    sparse: true, // Allow null values but ensure uniqueness when present
    trim: true,
    index: true
  },

  // Password for local authentication
  password: {
    type: String,
    required: function() {
      return this.authMethods.includes('local');
    }
  },

  // Personal information
  profile: {
    firstName: {
      type: String,
      trim: true
    },
    lastName: {
      type: String,
      trim: true
    },
    displayName: {
      type: String,
      trim: true
    },
    avatar: {
      type: String // URL to avatar image
    },
    bio: {
      type: String,
      maxlength: 500
    },
    phone: {
      type: String,
      trim: true
    },
    timezone: {
      type: String,
      default: 'UTC'
    },
    locale: {
      type: String,
      default: 'en'
    }
  },

  // Authentication methods used by this user
  authMethods: [{
    type: String,
    enum: ['local', 'google', 'github', 'saml', 'ldap', 'magic-link', 'otp', 'webauthn'],
    default: ['local']
  }],

  // External provider information
  providers: {
    google: {
      id: String,
      email: String,
      verified: { type: Boolean, default: false }
    },
    github: {
      id: String,
      username: String,
      email: String
    },
    saml: {
      nameId: String,
      sessionIndex: String,
      issuer: String
    },
    ldap: {
      dn: String,
      cn: String,
      uid: String
    }
  },

  // Account status
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended', 'pending'],
    default: 'pending'
  },

  // Email verification
  emailVerified: {
    type: Boolean,
    default: false
  },
  
  emailVerificationToken: {
    type: String,
    sparse: true
  },
  
  emailVerificationExpires: {
    type: Date
  },

  // Password reset
  passwordResetToken: {
    type: String,
    sparse: true
  },
  
  passwordResetExpires: {
    type: Date
  },

  // Multi-factor authentication
  mfa: {
    enabled: {
      type: Boolean,
      default: false
    },
    secret: {
      type: String // TOTP secret
    },
    backupCodes: [{
      code: String,
      used: { type: Boolean, default: false },
      usedAt: Date
    }],
    methods: [{
      type: String,
      enum: ['totp', 'sms', 'email', 'webauthn']
    }]
  },

  // WebAuthn credentials
  webauthnCredentials: [{
    credentialId: Buffer,
    publicKey: Buffer,
    counter: Number,
    deviceName: String,
    createdAt: { type: Date, default: Date.now }
  }],

  // Roles and permissions
  roles: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],

  permissions: [{
    type: String
  }],

  // Security settings
  security: {
    lastPasswordChange: {
      type: Date,
      default: Date.now
    },
    passwordHistory: [{
      hash: String,
      createdAt: { type: Date, default: Date.now }
    }],
    loginAttempts: {
      type: Number,
      default: 0
    },
    lockUntil: Date,
    lastLogin: Date,
    lastLoginIP: String,
    loginHistory: [{
      ip: String,
      userAgent: String,
      timestamp: { type: Date, default: Date.now },
      success: Boolean,
      strategy: String
    }]
  },

  // Preferences
  preferences: {
    notifications: {
      email: { type: Boolean, default: true },
      sms: { type: Boolean, default: false },
      push: { type: Boolean, default: true }
    },
    privacy: {
      profileVisible: { type: Boolean, default: true },
      emailVisible: { type: Boolean, default: false }
    },
    security: {
      requireMFA: { type: Boolean, default: false },
      sessionTimeout: { type: Number, default: 3600000 } // 1 hour in ms
    }
  },

  // Metadata
  metadata: {
    source: {
      type: String,
      enum: ['registration', 'oauth', 'saml', 'ldap', 'admin', 'import'],
      default: 'registration'
    },
    tags: [String],
    notes: String
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.passwordResetToken;
      delete ret.emailVerificationToken;
      delete ret.mfa.secret;
      delete ret.security.passwordHistory;
      return ret;
    }
  }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ 'providers.google.id': 1 });
userSchema.index({ 'providers.github.id': 1 });
userSchema.index({ 'providers.saml.nameId': 1 });
userSchema.index({ 'providers.ldap.dn': 1 });
userSchema.index({ status: 1 });
userSchema.index({ createdAt: -1 });

// Virtual for full name
userSchema.virtual('profile.fullName').get(function() {
  if (this.profile.firstName && this.profile.lastName) {
    return `${this.profile.firstName} ${this.profile.lastName}`;
  }
  return this.profile.displayName || this.username || this.email;
});

// Virtual for account locked status
userSchema.virtual('isLocked').get(function() {
  return !!(this.security.lockUntil && this.security.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only hash password if it's modified and not already hashed
  if (!this.isModified('password') || !this.password) {
    return next();
  }

  try {
    // Hash password
    const salt = await bcrypt.genSalt(config.security.bcryptRounds);
    this.password = await bcrypt.hash(this.password, salt);
    
    // Add to password history
    if (this.security.passwordHistory.length >= 5) {
      this.security.passwordHistory.shift(); // Keep only last 5 passwords
    }
    this.security.passwordHistory.push({
      hash: this.password,
      createdAt: new Date()
    });
    
    this.security.lastPasswordChange = new Date();
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) {
    return false;
  }
  return bcrypt.compare(candidatePassword, this.password);
};

// Method to check if password was used recently
userSchema.methods.isPasswordRecentlyUsed = async function(candidatePassword) {
  for (const historyEntry of this.security.passwordHistory) {
    if (await bcrypt.compare(candidatePassword, historyEntry.hash)) {
      return true;
    }
  }
  return false;
};

// Method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.security.lockUntil && this.security.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { 'security.lockUntil': 1 },
      $set: { 'security.loginAttempts': 1 }
    });
  }
  
  const updates = { $inc: { 'security.loginAttempts': 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.security.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { 'security.lockUntil': Date.now() + 2 * 60 * 60 * 1000 };
  }
  
  return this.updateOne(updates);
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: {
      'security.loginAttempts': 1,
      'security.lockUntil': 1
    }
  });
};

// Method to record successful login
userSchema.methods.recordLogin = function(ip, userAgent, strategy = 'local') {
  const loginRecord = {
    ip,
    userAgent,
    timestamp: new Date(),
    success: true,
    strategy
  };

  // Keep only last 10 login records
  if (this.security.loginHistory.length >= 10) {
    this.security.loginHistory.shift();
  }
  
  this.security.loginHistory.push(loginRecord);
  this.security.lastLogin = new Date();
  this.security.lastLoginIP = ip;
  
  return this.save();
};

// Method to record failed login
userSchema.methods.recordFailedLogin = function(ip, userAgent, strategy = 'local') {
  const loginRecord = {
    ip,
    userAgent,
    timestamp: new Date(),
    success: false,
    strategy
  };

  // Keep only last 10 login records
  if (this.security.loginHistory.length >= 10) {
    this.security.loginHistory.shift();
  }
  
  this.security.loginHistory.push(loginRecord);
  
  return this.save();
};

// Method to add authentication method
userSchema.methods.addAuthMethod = function(method) {
  if (!this.authMethods.includes(method)) {
    this.authMethods.push(method);
  }
  return this;
};

// Method to remove authentication method
userSchema.methods.removeAuthMethod = function(method) {
  this.authMethods = this.authMethods.filter(m => m !== method);
  return this;
};

// Method to check if user has permission
userSchema.methods.hasPermission = function(permission) {
  return this.permissions.includes(permission);
};

// Method to add permission
userSchema.methods.addPermission = function(permission) {
  if (!this.permissions.includes(permission)) {
    this.permissions.push(permission);
  }
  return this;
};

// Method to remove permission
userSchema.methods.removePermission = function(permission) {
  this.permissions = this.permissions.filter(p => p !== permission);
  return this;
};

// Method to generate MFA backup codes
userSchema.methods.generateBackupCodes = function() {
  const codes = [];
  for (let i = 0; i < 10; i++) {
    codes.push({
      code: Math.random().toString(36).substring(2, 10).toUpperCase(),
      used: false
    });
  }
  this.mfa.backupCodes = codes;
  return codes.map(c => c.code);
};

// Method to use MFA backup code
userSchema.methods.useBackupCode = function(code) {
  const backupCode = this.mfa.backupCodes.find(c => c.code === code && !c.used);
  if (backupCode) {
    backupCode.used = true;
    backupCode.usedAt = new Date();
    return true;
  }
  return false;
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

// Static method to find by provider
userSchema.statics.findByProvider = function(provider, providerId) {
  const query = {};
  query[`providers.${provider}.id`] = providerId;
  return this.findOne(query);
};

module.exports = mongoose.model('User', userSchema);

