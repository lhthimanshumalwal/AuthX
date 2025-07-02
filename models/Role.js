const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  // Basic Information
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

  // Permissions
  permissions: [{
    type: String,
    trim: true
  }],

  // Hierarchy
  parent: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  },
  children: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role'
  }],
  level: {
    type: Number,
    default: 0
  },

  // Status
  status: {
    type: String,
    enum: ['active', 'inactive'],
    default: 'active'
  },

  // System Role Flag
  isSystem: {
    type: Boolean,
    default: false
  },

  // Role Type
  type: {
    type: String,
    enum: ['system', 'custom', 'inherited'],
    default: 'custom'
  },

  // Metadata
  metadata: mongoose.Schema.Types.Mixed,
  tags: [String],

  // Audit Trail
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true
});

// Indexes
roleSchema.index({ name: 1, status: 1 });
roleSchema.index({ parent: 1 });
roleSchema.index({ level: 1 });
roleSchema.index({ type: 1 });

// Virtual for user count
roleSchema.virtual('userCount', {
  ref: 'User',
  localField: '_id',
  foreignField: 'roles',
  count: true
});

// Method to get all permissions (including inherited)
roleSchema.methods.getAllPermissions = async function() {
  const allPermissions = new Set(this.permissions);
  
  // Get permissions from parent roles
  if (this.parent) {
    const parent = await this.constructor.findById(this.parent);
    if (parent) {
      const parentPermissions = await parent.getAllPermissions();
      parentPermissions.forEach(permission => allPermissions.add(permission));
    }
  }
  
  return Array.from(allPermissions);
};

// Method to check if role has permission
roleSchema.methods.hasPermission = async function(permission) {
  const allPermissions = await this.getAllPermissions();
  return allPermissions.includes(permission);
};

// Method to add permission
roleSchema.methods.addPermission = function(permission) {
  if (!this.permissions.includes(permission)) {
    this.permissions.push(permission);
  }
  return this.save();
};

// Method to remove permission
roleSchema.methods.removePermission = function(permission) {
  this.permissions = this.permissions.filter(p => p !== permission);
  return this.save();
};

// Static method to create default roles
roleSchema.statics.createDefaultRoles = async function() {
  const defaultRoles = [
    {
      name: 'super_admin',
      displayName: 'Super Administrator',
      description: 'Full system access with all permissions',
      permissions: ['*'],
      isSystem: true,
      type: 'system',
      level: 0
    },
    {
      name: 'admin',
      displayName: 'Administrator',
      description: 'Administrative access to manage users and system settings',
      permissions: [
        'users:read',
        'users:write',
        'users:delete',
        'roles:read',
        'roles:write',
        'settings:read',
        'settings:write',
        'audit:read'
      ],
      isSystem: true,
      type: 'system',
      level: 1
    },
    {
      name: 'moderator',
      displayName: 'Moderator',
      description: 'Moderate users and content',
      permissions: [
        'users:read',
        'users:moderate',
        'content:moderate',
        'reports:read',
        'reports:write'
      ],
      isSystem: true,
      type: 'system',
      level: 2
    },
    {
      name: 'user',
      displayName: 'User',
      description: 'Standard user with basic permissions',
      permissions: [
        'profile:read',
        'profile:write',
        'content:read',
        'content:write'
      ],
      isSystem: true,
      type: 'system',
      level: 3
    },
    {
      name: 'guest',
      displayName: 'Guest',
      description: 'Limited access for unauthenticated users',
      permissions: [
        'content:read'
      ],
      isSystem: true,
      type: 'system',
      level: 4
    }
  ];

  for (const roleData of defaultRoles) {
    const existingRole = await this.findOne({ name: roleData.name });
    if (!existingRole) {
      await this.create(roleData);
    }
  }
};

// Static method to get role hierarchy
roleSchema.statics.getHierarchy = async function() {
  const roles = await this.find({ status: 'active' }).sort({ level: 1 });
  const hierarchy = {};
  
  roles.forEach(role => {
    if (!role.parent) {
      hierarchy[role._id] = { ...role.toObject(), children: [] };
    }
  });
  
  roles.forEach(role => {
    if (role.parent && hierarchy[role.parent]) {
      hierarchy[role.parent].children.push(role.toObject());
    }
  });
  
  return Object.values(hierarchy);
};

// Pre-save middleware to set level based on parent
roleSchema.pre('save', async function(next) {
  if (this.parent && this.isModified('parent')) {
    const parent = await this.constructor.findById(this.parent);
    if (parent) {
      this.level = parent.level + 1;
    }
  }
  next();
});

// Pre-remove middleware to handle children
roleSchema.pre('remove', async function(next) {
  // Update children to remove parent reference
  await this.constructor.updateMany(
    { parent: this._id },
    { $unset: { parent: 1 }, $inc: { level: -1 } }
  );
  
  // Remove role from users
  await mongoose.model('User').updateMany(
    { roles: this._id },
    { $pull: { roles: this._id } }
  );
  
  next();
});

module.exports = mongoose.model('Role', roleSchema);

