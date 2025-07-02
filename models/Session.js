const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  // Session Identification
  sessionId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },

  // Session Data
  data: mongoose.Schema.Types.Mixed,

  // Device and Location Information
  deviceInfo: {
    userAgent: String,
    browser: String,
    os: String,
    device: String,
    ip: String,
    location: {
      country: String,
      region: String,
      city: String,
      timezone: String,
      coordinates: {
        lat: Number,
        lng: Number
      }
    }
  },

  // Session Status
  status: {
    type: String,
    enum: ['active', 'expired', 'revoked', 'suspicious'],
    default: 'active'
  },

  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  lastActivity: {
    type: Date,
    default: Date.now,
    index: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 }
  },

  // Security Information
  loginMethod: {
    type: String,
    enum: ['password', 'oauth', 'saml', 'ldap', 'magic-link', '2fa'],
    required: true
  },
  ipHistory: [{
    ip: String,
    timestamp: { type: Date, default: Date.now },
    location: String
  }],
  
  // Flags
  isRemembered: {
    type: Boolean,
    default: false
  },
  isSuspicious: {
    type: Boolean,
    default: false
  },
  
  // Metadata
  metadata: mongoose.Schema.Types.Mixed
}, {
  timestamps: true
});

// Indexes
sessionSchema.index({ userId: 1, status: 1 });
sessionSchema.index({ createdAt: -1 });
sessionSchema.index({ lastActivity: -1 });
sessionSchema.index({ expiresAt: 1 });

// Virtual for session duration
sessionSchema.virtual('duration').get(function() {
  return this.lastActivity - this.createdAt;
});

// Virtual for time until expiry
sessionSchema.virtual('timeUntilExpiry').get(function() {
  return this.expiresAt - Date.now();
});

// Virtual for is expired
sessionSchema.virtual('isExpired').get(function() {
  return this.expiresAt < Date.now() || this.status === 'expired';
});

// Virtual for is active
sessionSchema.virtual('isActive').get(function() {
  return this.status === 'active' && !this.isExpired;
});

// Method to update last activity
sessionSchema.methods.updateActivity = function(ip) {
  this.lastActivity = new Date();
  
  // Track IP changes
  if (ip && ip !== this.deviceInfo.ip) {
    this.ipHistory.push({
      ip: ip,
      timestamp: new Date()
    });
    
    // Keep only last 10 IP addresses
    if (this.ipHistory.length > 10) {
      this.ipHistory = this.ipHistory.slice(-10);
    }
    
    // Update current IP
    this.deviceInfo.ip = ip;
    
    // Flag as suspicious if too many IP changes
    if (this.ipHistory.length > 5) {
      this.isSuspicious = true;
    }
  }
  
  return this.save();
};

// Method to extend session
sessionSchema.methods.extend = function(duration) {
  this.expiresAt = new Date(Date.now() + duration);
  return this.save();
};

// Method to revoke session
sessionSchema.methods.revoke = function(reason) {
  this.status = 'revoked';
  this.metadata = { 
    ...this.metadata, 
    revokedAt: new Date(),
    revokeReason: reason 
  };
  return this.save();
};

// Method to mark as suspicious
sessionSchema.methods.markSuspicious = function(reason) {
  this.isSuspicious = true;
  this.status = 'suspicious';
  this.metadata = { 
    ...this.metadata, 
    suspiciousAt: new Date(),
    suspiciousReason: reason 
  };
  return this.save();
};

// Static method to cleanup expired sessions
sessionSchema.statics.cleanupExpired = async function() {
  const result = await this.deleteMany({
    $or: [
      { expiresAt: { $lt: new Date() } },
      { status: 'expired' }
    ]
  });
  return result.deletedCount;
};

// Static method to get active sessions for user
sessionSchema.statics.getActiveSessions = function(userId) {
  return this.find({
    userId: userId,
    status: 'active',
    expiresAt: { $gt: new Date() }
  }).sort({ lastActivity: -1 });
};

// Static method to revoke all sessions for user
sessionSchema.statics.revokeAllForUser = async function(userId, reason = 'user_request') {
  const result = await this.updateMany(
    { 
      userId: userId, 
      status: 'active' 
    },
    { 
      status: 'revoked',
      $set: {
        'metadata.revokedAt': new Date(),
        'metadata.revokeReason': reason
      }
    }
  );
  return result.modifiedCount;
};

// Static method to get session statistics
sessionSchema.statics.getStatistics = async function(userId) {
  const stats = await this.aggregate([
    { $match: { userId: mongoose.Types.ObjectId(userId) } },
    {
      $group: {
        _id: null,
        totalSessions: { $sum: 1 },
        activeSessions: {
          $sum: {
            $cond: [
              { 
                $and: [
                  { $eq: ['$status', 'active'] },
                  { $gt: ['$expiresAt', new Date()] }
                ]
              },
              1,
              0
            ]
          }
        },
        suspiciousSessions: {
          $sum: { $cond: ['$isSuspicious', 1, 0] }
        },
        avgSessionDuration: {
          $avg: { $subtract: ['$lastActivity', '$createdAt'] }
        },
        lastActivity: { $max: '$lastActivity' }
      }
    }
  ]);
  
  return stats[0] || {
    totalSessions: 0,
    activeSessions: 0,
    suspiciousSessions: 0,
    avgSessionDuration: 0,
    lastActivity: null
  };
};

// Pre-save middleware to set expiry if not set
sessionSchema.pre('save', function(next) {
  if (!this.expiresAt) {
    // Default to 24 hours
    this.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  }
  next();
});

module.exports = mongoose.model('Session', sessionSchema);

