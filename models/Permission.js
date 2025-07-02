const mongoose = require('mongoose');

const permissionSchema = new mongoose.Schema({
  // Permission identification
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    index: true
  },

  displayName: {
    type: String,
    required: true,
    trim: true
  },

  description: {
    type: String,
    trim: true,
    maxlength: 500
  },

  // Permission categorization
  resource: {
    type: String,
    required: true,
    trim: true,
    lowercase: true,
    index: true
  },

  action: {
    type: String,
    required: true,
    enum: ['create', 'read', 'update', 'delete', 'execute', 'manage', '*'],
    index: true
  },

  // Permission scope and constraints
  scope: {
    type: String,
    enum: ['global', 'organization', 'team', 'user', 'resource'],
    default: 'global'
  },

  conditions: [{
    field: String,
    operator: {
      type: String,
      enum: ['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'in', 'nin', 'exists', 'regex']
    },
    value: mongoose.Schema.Types.Mixed
  }],

  // Permission metadata
  category: {
    type: String,
    enum: ['system', 'user', 'content', 'admin', 'api', 'custom'],
    default: 'custom',
    index: true
  },

  priority: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },

  // Permission status
  status: {
    type: String,
    enum: ['active', 'inactive', 'deprecated'],
    default: 'active'
  },

  isSystem: {
    type: Boolean,
    default: false
  },

  // Risk and security level
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },

  requiresApproval: {
    type: Boolean,
    default: false
  },

  // Permission dependencies
  dependencies: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }],

  conflicts: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }],

  // Audit information
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },

  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Compound indexes for performance
permissionSchema.index({ resource: 1, action: 1 });
permissionSchema.index({ category: 1, status: 1 });
permissionSchema.index({ riskLevel: 1 });

// Virtual for full permission string
permissionSchema.virtual('fullName').get(function() {
  return `${this.resource}:${this.action}`;
});

// Pre-save middleware
permissionSchema.pre('save', function(next) {
  // Auto-generate name if not provided
  if (!this.name) {
    this.name = `${this.resource}:${this.action}`;
  }
  
  // Ensure system permissions cannot be modified inappropriately
  if (this.isSystem && this.isModified() && !this.isNew) {
    const modifiedPaths = this.modifiedPaths();
    const allowedModifications = ['updatedBy', 'updatedAt', 'status'];
    const hasDisallowedModifications = modifiedPaths.some(path => 
      !allowedModifications.includes(path)
    );
    
    if (hasDisallowedModifications) {
      return next(new Error('System permissions cannot be modified'));
    }
  }
  
  next();
});

// Pre-remove middleware
permissionSchema.pre('remove', function(next) {
  if (this.isSystem) {
    return next(new Error('System permissions cannot be deleted'));
  }
  next();
});

// Method to check if permission matches a given resource and action
permissionSchema.methods.matches = function(resource, action) {
  // Wildcard permission matches everything
  if (this.resource === '*' && this.action === '*') {
    return true;
  }
  
  // Wildcard resource matches any resource with same action
  if (this.resource === '*' && this.action === action) {
    return true;
  }
  
  // Wildcard action matches any action on same resource
  if (this.resource === resource && this.action === '*') {
    return true;
  }
  
  // Exact match
  return this.resource === resource && this.action === action;
};

// Method to evaluate conditions
permissionSchema.methods.evaluateConditions = function(context = {}) {
  if (!this.conditions || this.conditions.length === 0) {
    return true;
  }
  
  return this.conditions.every(condition => {
    const contextValue = context[condition.field];
    const conditionValue = condition.value;
    
    switch (condition.operator) {
      case 'eq':
        return contextValue === conditionValue;
      case 'ne':
        return contextValue !== conditionValue;
      case 'gt':
        return contextValue > conditionValue;
      case 'gte':
        return contextValue >= conditionValue;
      case 'lt':
        return contextValue < conditionValue;
      case 'lte':
        return contextValue <= conditionValue;
      case 'in':
        return Array.isArray(conditionValue) && conditionValue.includes(contextValue);
      case 'nin':
        return Array.isArray(conditionValue) && !conditionValue.includes(contextValue);
      case 'exists':
        return conditionValue ? contextValue !== undefined : contextValue === undefined;
      case 'regex':
        return new RegExp(conditionValue).test(contextValue);
      default:
        return false;
    }
  });
};

// Static method to find by resource and action
permissionSchema.statics.findByResourceAction = function(resource, action) {
  return this.find({
    $or: [
      { resource: resource, action: action },
      { resource: resource, action: '*' },
      { resource: '*', action: action },
      { resource: '*', action: '*' }
    ],
    status: 'active'
  });
};

// Static method to find by category
permissionSchema.statics.findByCategory = function(category) {
  return this.find({ category: category, status: 'active' });
};

// Static method to create system permissions
permissionSchema.statics.createSystemPermissions = async function() {
  const systemPermissions = [
    // Wildcard permissions
    {
      name: '*',
      displayName: 'All Permissions',
      description: 'Grants access to all system functions',
      resource: '*',
      action: '*',
      category: 'system',
      riskLevel: 'critical',
      isSystem: true,
      requiresApproval: true
    },

    // User management permissions
    {
      name: 'users:create',
      displayName: 'Create Users',
      description: 'Create new user accounts',
      resource: 'users',
      action: 'create',
      category: 'user',
      riskLevel: 'medium',
      isSystem: true
    },
    {
      name: 'users:read',
      displayName: 'Read Users',
      description: 'View user information',
      resource: 'users',
      action: 'read',
      category: 'user',
      riskLevel: 'low',
      isSystem: true
    },
    {
      name: 'users:update',
      displayName: 'Update Users',
      description: 'Modify user information',
      resource: 'users',
      action: 'update',
      category: 'user',
      riskLevel: 'medium',
      isSystem: true
    },
    {
      name: 'users:delete',
      displayName: 'Delete Users',
      description: 'Delete user accounts',
      resource: 'users',
      action: 'delete',
      category: 'user',
      riskLevel: 'high',
      isSystem: true,
      requiresApproval: true
    },

    // Role management permissions
    {
      name: 'roles:create',
      displayName: 'Create Roles',
      description: 'Create new roles',
      resource: 'roles',
      action: 'create',
      category: 'admin',
      riskLevel: 'high',
      isSystem: true
    },
    {
      name: 'roles:read',
      displayName: 'Read Roles',
      description: 'View role information',
      resource: 'roles',
      action: 'read',
      category: 'admin',
      riskLevel: 'low',
      isSystem: true
    },
    {
      name: 'roles:update',
      displayName: 'Update Roles',
      description: 'Modify role information',
      resource: 'roles',
      action: 'update',
      category: 'admin',
      riskLevel: 'high',
      isSystem: true
    },
    {
      name: 'roles:delete',
      displayName: 'Delete Roles',
      description: 'Delete roles',
      resource: 'roles',
      action: 'delete',
      category: 'admin',
      riskLevel: 'high',
      isSystem: true,
      requiresApproval: true
    },

    // Permission management
    {
      name: 'permissions:read',
      displayName: 'Read Permissions',
      description: 'View permission information',
      resource: 'permissions',
      action: 'read',
      category: 'admin',
      riskLevel: 'low',
      isSystem: true
    },

    // Authentication permissions
    {
      name: 'auth:login',
      displayName: 'Login',
      description: 'Authenticate and login to the system',
      resource: 'auth',
      action: 'execute',
      category: 'system',
      riskLevel: 'low',
      isSystem: true
    },
    {
      name: 'auth:logout',
      displayName: 'Logout',
      description: 'Logout from the system',
      resource: 'auth',
      action: 'execute',
      category: 'system',
      riskLevel: 'low',
      isSystem: true
    },
    {
      name: 'auth:register',
      displayName: 'Register',
      description: 'Register new user account',
      resource: 'auth',
      action: 'create',
      category: 'system',
      riskLevel: 'low',
      isSystem: true
    },

    // Profile permissions
    {
      name: 'profile:read',
      displayName: 'Read Profile',
      description: 'View own profile information',
      resource: 'profile',
      action: 'read',
      category: 'user',
      riskLevel: 'low',
      isSystem: true
    },
    {
      name: 'profile:update',
      displayName: 'Update Profile',
      description: 'Modify own profile information',
      resource: 'profile',
      action: 'update',
      category: 'user',
      riskLevel: 'low',
      isSystem: true
    },

    // System permissions
    {
      name: 'system:read',
      displayName: 'Read System Info',
      description: 'View system information and statistics',
      resource: 'system',
      action: 'read',
      category: 'system',
      riskLevel: 'medium',
      isSystem: true
    },
    {
      name: 'system:manage',
      displayName: 'Manage System',
      description: 'Manage system configuration and settings',
      resource: 'system',
      action: 'manage',
      category: 'system',
      riskLevel: 'critical',
      isSystem: true,
      requiresApproval: true
    },

    // Audit permissions
    {
      name: 'audit:read',
      displayName: 'Read Audit Logs',
      description: 'View audit logs and security events',
      resource: 'audit',
      action: 'read',
      category: 'admin',
      riskLevel: 'medium',
      isSystem: true
    },

    // API permissions
    {
      name: 'api:access',
      displayName: 'API Access',
      description: 'Access API endpoints',
      resource: 'api',
      action: 'execute',
      category: 'api',
      riskLevel: 'low',
      isSystem: true
    }
  ];

  const createdPermissions = [];
  
  for (const permissionData of systemPermissions) {
    try {
      const existingPermission = await this.findOne({ name: permissionData.name });
      if (!existingPermission) {
        const permission = new this(permissionData);
        await permission.save();
        createdPermissions.push(permission);
      }
    } catch (error) {
      console.error(`Failed to create system permission ${permissionData.name}:`, error);
    }
  }
  
  return createdPermissions;
};

// Static method to get permissions by risk level
permissionSchema.statics.getByRiskLevel = function(riskLevel) {
  return this.find({ riskLevel: riskLevel, status: 'active' });
};

// Static method to get permissions requiring approval
permissionSchema.statics.getRequiringApproval = function() {
  return this.find({ requiresApproval: true, status: 'active' });
};

module.exports = mongoose.model('Permission', permissionSchema);

