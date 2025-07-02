const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  // Role identification
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

  // Role hierarchy and inheritance
  level: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },

  parent: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
    default: null
  },

  children: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],

  // Permissions associated with this role
  permissions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Permission'
  }],

  // Direct permission strings (for simple permissions)
  directPermissions: [{
    type: String,
    trim: true
  }],

  // Role status and configuration
  status: {
    type: String,
    enum: ['active', 'inactive', 'deprecated'],
    default: 'active'
  },

  isSystem: {
    type: Boolean,
    default: false // System roles cannot be deleted
  },

  isDefault: {
    type: Boolean,
    default: false // Default role assigned to new users
  },

  // Role constraints
  constraints: {
    maxUsers: {
      type: Number,
      default: null // null means unlimited
    },
    expiresAfter: {
      type: Number, // Duration in milliseconds
      default: null // null means no expiration
    },
    requiresApproval: {
      type: Boolean,
      default: false
    }
  },

  // Role metadata
  metadata: {
    color: {
      type: String,
      default: '#6B7280' // Default gray color
    },
    icon: {
      type: String,
      default: 'user'
    },
    category: {
      type: String,
      enum: ['system', 'admin', 'user', 'service', 'custom'],
      default: 'custom'
    },
    tags: [String]
  },

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

// Indexes for performance
roleSchema.index({ name: 1 });
roleSchema.index({ level: 1 });
roleSchema.index({ status: 1 });
roleSchema.index({ isDefault: 1 });
roleSchema.index({ 'metadata.category': 1 });

// Virtual for user count
roleSchema.virtual('userCount', {
  ref: 'User',
  localField: '_id',
  foreignField: 'roles',
  count: true
});

// Virtual for inherited permissions
roleSchema.virtual('allPermissions').get(function() {
  // This would be populated by a method that traverses the role hierarchy
  return this.directPermissions;
});

// Pre-save middleware
roleSchema.pre('save', function(next) {
  // Ensure system roles cannot be modified inappropriately
  if (this.isSystem && this.isModified() && !this.isNew) {
    const modifiedPaths = this.modifiedPaths();
    const allowedModifications = ['updatedBy', 'updatedAt'];
    const hasDisallowedModifications = modifiedPaths.some(path => 
      !allowedModifications.includes(path)
    );
    
    if (hasDisallowedModifications) {
      return next(new Error('System roles cannot be modified'));
    }
  }
  
  next();
});

// Pre-remove middleware
roleSchema.pre('remove', function(next) {
  if (this.isSystem) {
    return next(new Error('System roles cannot be deleted'));
  }
  next();
});

// Method to check if role has permission
roleSchema.methods.hasPermission = function(permission) {
  return this.directPermissions.includes(permission);
};

// Method to add permission
roleSchema.methods.addPermission = function(permission) {
  if (!this.directPermissions.includes(permission)) {
    this.directPermissions.push(permission);
  }
  return this;
};

// Method to remove permission
roleSchema.methods.removePermission = function(permission) {
  this.directPermissions = this.directPermissions.filter(p => p !== permission);
  return this;
};

// Method to get all permissions including inherited ones
roleSchema.methods.getAllPermissions = async function() {
  const permissions = [...this.directPermissions];
  
  // Get permissions from parent roles
  if (this.parent) {
    await this.populate('parent');
    const parentPermissions = await this.parent.getAllPermissions();
    permissions.push(...parentPermissions);
  }
  
  // Remove duplicates
  return [...new Set(permissions)];
};

// Method to check if role is ancestor of another role
roleSchema.methods.isAncestorOf = async function(roleId) {
  const role = await this.constructor.findById(roleId);
  if (!role) return false;
  
  let currentRole = role;
  while (currentRole.parent) {
    await currentRole.populate('parent');
    if (currentRole.parent._id.equals(this._id)) {
      return true;
    }
    currentRole = currentRole.parent;
  }
  
  return false;
};

// Method to check if role is descendant of another role
roleSchema.methods.isDescendantOf = async function(roleId) {
  const role = await this.constructor.findById(roleId);
  if (!role) return false;
  
  return await role.isAncestorOf(this._id);
};

// Static method to find default role
roleSchema.statics.findDefault = function() {
  return this.findOne({ isDefault: true, status: 'active' });
};

// Static method to find by category
roleSchema.statics.findByCategory = function(category) {
  return this.find({ 'metadata.category': category, status: 'active' });
};

// Static method to create system roles
roleSchema.statics.createSystemRoles = async function() {
  const systemRoles = [
    {
      name: 'super_admin',
      displayName: 'Super Administrator',
      description: 'Full system access with all permissions',
      level: 100,
      isSystem: true,
      directPermissions: ['*'], // Wildcard permission
      metadata: {
        category: 'system',
        color: '#DC2626',
        icon: 'shield'
      }
    },
    {
      name: 'admin',
      displayName: 'Administrator',
      description: 'Administrative access to most system functions',
      level: 90,
      isSystem: true,
      directPermissions: [
        'users:read', 'users:write', 'users:delete',
        'roles:read', 'roles:write',
        'permissions:read',
        'audit:read',
        'system:read'
      ],
      metadata: {
        category: 'admin',
        color: '#DC2626',
        icon: 'user-shield'
      }
    },
    {
      name: 'moderator',
      displayName: 'Moderator',
      description: 'Limited administrative access',
      level: 50,
      isSystem: true,
      directPermissions: [
        'users:read', 'users:write',
        'roles:read',
        'audit:read'
      ],
      metadata: {
        category: 'admin',
        color: '#F59E0B',
        icon: 'user-check'
      }
    },
    {
      name: 'user',
      displayName: 'User',
      description: 'Standard user with basic permissions',
      level: 10,
      isSystem: true,
      isDefault: true,
      directPermissions: [
        'profile:read', 'profile:write',
        'auth:login', 'auth:logout'
      ],
      metadata: {
        category: 'user',
        color: '#6B7280',
        icon: 'user'
      }
    },
    {
      name: 'guest',
      displayName: 'Guest',
      description: 'Limited access for unauthenticated users',
      level: 0,
      isSystem: true,
      directPermissions: [
        'auth:login', 'auth:register'
      ],
      metadata: {
        category: 'user',
        color: '#9CA3AF',
        icon: 'user-circle'
      }
    }
  ];

  const createdRoles = [];
  
  for (const roleData of systemRoles) {
    try {
      const existingRole = await this.findOne({ name: roleData.name });
      if (!existingRole) {
        const role = new this(roleData);
        await role.save();
        createdRoles.push(role);
      }
    } catch (error) {
      console.error(`Failed to create system role ${roleData.name}:`, error);
    }
  }
  
  return createdRoles;
};

// Static method to get role hierarchy
roleSchema.statics.getHierarchy = async function() {
  const roles = await this.find({ status: 'active' })
    .populate('parent')
    .populate('children')
    .sort({ level: -1 });
  
  const hierarchy = {};
  const rootRoles = [];
  
  roles.forEach(role => {
    hierarchy[role._id] = {
      ...role.toObject(),
      children: []
    };
  });
  
  roles.forEach(role => {
    if (role.parent) {
      if (hierarchy[role.parent._id]) {
        hierarchy[role.parent._id].children.push(hierarchy[role._id]);
      }
    } else {
      rootRoles.push(hierarchy[role._id]);
    }
  });
  
  return rootRoles;
};

module.exports = mongoose.model('Role', roleSchema);

