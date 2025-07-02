const { Strategy: LdapStrategy } = require('passport-ldapauth');
const config = require('../../config/config');
const userService = require('../../services/userService');
const logger = require('../../utils/logger');
const auditService = require('../../services/auditService');

/**
 * LDAP/Active Directory Authentication Strategy
 */
const createLdapStrategy = () => {
  const options = {
    server: {
      url: config.ldap.server.url,
      bindDN: config.ldap.server.bindDN,
      bindCredentials: config.ldap.server.bindCredentials,
      searchBase: config.ldap.server.searchBase,
      searchFilter: config.ldap.server.searchFilter,
      searchAttributes: config.ldap.server.searchAttributes || ['uid', 'mail', 'cn', 'sn', 'givenName', 'memberOf'],
      tlsOptions: {
        rejectUnauthorized: false // Set to true in production with proper certificates
      }
    },
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
  };

  return new LdapStrategy(options, async (req, ldapUser, done) => {
    try {
      logger.debug('LDAP authentication attempt', {
        username: ldapUser.uid || ldapUser.cn,
        email: ldapUser.mail,
        dn: ldapUser.dn,
        ip: req.ip
      });

      // Validate LDAP user data
      if (!ldapUser.mail && !ldapUser.uid) {
        logger.warn('Invalid LDAP user data - missing email and uid', {
          ldapUser: ldapUser,
          ip: req.ip
        });

        await auditService.log('ldap_auth_failed', {
          reason: 'missing_user_data',
          dn: ldapUser.dn,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Invalid LDAP user data' 
        });
      }

      // Extract user information from LDAP attributes
      const userInfo = extractLdapUserInfo(ldapUser);

      if (!userInfo.email) {
        logger.warn('LDAP user missing email', {
          username: ldapUser.uid,
          dn: ldapUser.dn,
          ip: req.ip
        });

        await auditService.log('ldap_auth_failed', {
          reason: 'missing_email',
          username: ldapUser.uid,
          dn: ldapUser.dn,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Email address is required for LDAP authentication' 
        });
      }

      // Create or update user from LDAP
      const user = await createOrUpdateLdapUser(userInfo, ldapUser);

      if (!user) {
        logger.error('Failed to create/update LDAP user', {
          username: ldapUser.uid,
          email: userInfo.email,
          dn: ldapUser.dn,
          ip: req.ip
        });

        await auditService.log('ldap_auth_failed', {
          reason: 'user_creation_failed',
          username: ldapUser.uid,
          email: userInfo.email,
          dn: ldapUser.dn,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Failed to create or update user account' 
        });
      }

      // Check if account is active
      if (user.status !== 'active') {
        logger.warn('LDAP authentication for inactive account', {
          userId: user._id,
          status: user.status,
          username: ldapUser.uid,
          ip: req.ip
        });

        await auditService.log('ldap_auth_failed', {
          userId: user._id,
          reason: 'account_inactive',
          status: user.status,
          username: ldapUser.uid,
          dn: ldapUser.dn,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Account is not active' 
        });
      }

      // Check if account is locked
      if (user.isLocked) {
        logger.warn('LDAP authentication for locked account', {
          userId: user._id,
          lockUntil: user.lockUntil,
          username: ldapUser.uid,
          ip: req.ip
        });

        await auditService.log('ldap_auth_failed', {
          userId: user._id,
          reason: 'account_locked',
          lockUntil: user.lockUntil,
          username: ldapUser.uid,
          dn: ldapUser.dn,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Account is temporarily locked' 
        });
      }

      // Create device info
      const deviceInfo = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        provider: 'ldap',
        timestamp: new Date()
      };

      // Add session to user
      if (req.session) {
        await user.addSession(req.session.id, deviceInfo);
      }

      // Log successful LDAP authentication
      await auditService.log('ldap_auth_success', {
        userId: user._id,
        email: user.email,
        username: ldapUser.uid,
        dn: ldapUser.dn,
        isNewUser: user.createdAt > new Date(Date.now() - 60000),
        deviceInfo
      });

      logger.info('LDAP authentication successful', {
        userId: user._id,
        email: user.email,
        username: ldapUser.uid,
        dn: ldapUser.dn,
        ip: req.ip
      });

      // Attach LDAP metadata
      user.authMethod = 'ldap';
      user.authTimestamp = new Date();
      user.ldapProfile = {
        dn: ldapUser.dn,
        uid: ldapUser.uid,
        attributes: ldapUser
      };

      return done(null, user);
    } catch (error) {
      logger.error('LDAP strategy error:', error);

      await auditService.log('ldap_auth_error', {
        error: error.message,
        username: ldapUser?.uid,
        dn: ldapUser?.dn,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return done(error);
    }
  });
};

/**
 * Extract user information from LDAP attributes
 */
function extractLdapUserInfo(ldapUser) {
  const userInfo = {
    email: ldapUser.mail || ldapUser.userPrincipalName,
    username: ldapUser.uid || ldapUser.sAMAccountName,
    firstName: ldapUser.givenName,
    lastName: ldapUser.sn,
    displayName: ldapUser.cn || ldapUser.displayName,
    department: ldapUser.department || ldapUser.ou,
    title: ldapUser.title,
    phone: ldapUser.telephoneNumber || ldapUser.mobile,
    groups: []
  };

  // Extract groups/roles from memberOf attribute
  if (ldapUser.memberOf) {
    if (Array.isArray(ldapUser.memberOf)) {
      userInfo.groups = ldapUser.memberOf.map(extractGroupName);
    } else {
      userInfo.groups = [extractGroupName(ldapUser.memberOf)];
    }
  }

  return userInfo;
}

/**
 * Extract group name from LDAP DN
 */
function extractGroupName(groupDn) {
  // Extract CN from DN (e.g., "CN=Administrators,OU=Groups,DC=example,DC=com" -> "Administrators")
  const match = groupDn.match(/^CN=([^,]+)/i);
  return match ? match[1] : groupDn;
}

/**
 * Create or update user from LDAP authentication
 */
async function createOrUpdateLdapUser(userInfo, ldapUser) {
  try {
    // Check if user exists by email
    let user = await userService.getUserByEmail(userInfo.email);

    if (user) {
      // Update existing user with LDAP data
      user.oauthProviders.ldap = {
        dn: ldapUser.dn,
        uid: ldapUser.uid,
        attributes: ldapUser
      };

      // Add LDAP to auth providers if not already present
      if (!user.authProviders.includes('ldap')) {
        user.authProviders.push('ldap');
      }

      // Update profile information
      if (userInfo.firstName && (!user.profile.firstName || user.profile.firstName !== userInfo.firstName)) {
        user.profile.firstName = userInfo.firstName;
      }
      if (userInfo.lastName && (!user.profile.lastName || user.profile.lastName !== userInfo.lastName)) {
        user.profile.lastName = userInfo.lastName;
      }
      if (userInfo.displayName && (!user.profile.displayName || user.profile.displayName !== userInfo.displayName)) {
        user.profile.displayName = userInfo.displayName;
      }

      // Update username if not set
      if (!user.username && userInfo.username) {
        user.username = userInfo.username;
      }

      // Sync LDAP groups to roles (if configured)
      if (config.ldap.syncGroups && userInfo.groups.length > 0) {
        await syncLdapGroupsToRoles(user, userInfo.groups);
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      logger.info('LDAP user updated', {
        userId: user._id,
        email: user.email,
        username: userInfo.username,
        dn: ldapUser.dn
      });
    } else {
      // Create new user
      const Role = require('../../models/Role');
      const defaultRole = await Role.findOne({ name: 'user' });

      const userData = {
        email: userInfo.email,
        username: userInfo.username,
        profile: {
          firstName: userInfo.firstName,
          lastName: userInfo.lastName,
          displayName: userInfo.displayName || `${userInfo.firstName} ${userInfo.lastName}`.trim()
        },
        authProviders: ['ldap'],
        oauthProviders: {
          ldap: {
            dn: ldapUser.dn,
            uid: ldapUser.uid,
            attributes: ldapUser
          }
        },
        status: 'active',
        emailVerified: true, // Assume LDAP emails are verified
        roles: defaultRole ? [defaultRole._id] : []
      };

      user = await userService.createUser(userData);

      // Sync LDAP groups to roles for new user
      if (config.ldap.syncGroups && userInfo.groups.length > 0) {
        await syncLdapGroupsToRoles(user, userInfo.groups);
      }

      logger.info('LDAP user created', {
        userId: user._id,
        email: user.email,
        username: userInfo.username,
        dn: ldapUser.dn
      });
    }

    return user;
  } catch (error) {
    logger.error('Error creating/updating LDAP user:', error);
    throw error;
  }
}

/**
 * Sync LDAP groups to user roles
 */
async function syncLdapGroupsToRoles(user, ldapGroups) {
  try {
    const Role = require('../../models/Role');
    
    // Define LDAP group to role mappings
    const groupRoleMappings = config.ldap.groupRoleMappings || {
      'Administrators': 'admin',
      'Domain Admins': 'admin',
      'Users': 'user',
      'Managers': 'moderator'
    };

    const rolesToAdd = [];
    
    // Map LDAP groups to roles
    for (const group of ldapGroups) {
      const roleName = groupRoleMappings[group];
      if (roleName) {
        const role = await Role.findOne({ name: roleName });
        if (role && !user.roles.some(r => r.equals(role._id))) {
          rolesToAdd.push(role._id);
        }
      }
    }

    // Add new roles
    if (rolesToAdd.length > 0) {
      user.roles.push(...rolesToAdd);
      await user.save();
      
      logger.info('Synced LDAP groups to roles', {
        userId: user._id,
        ldapGroups: ldapGroups,
        addedRoles: rolesToAdd.length
      });
    }
  } catch (error) {
    logger.error('Error syncing LDAP groups to roles:', error);
  }
}

module.exports = createLdapStrategy;

