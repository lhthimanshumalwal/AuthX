const { Strategy: SamlStrategy } = require('passport-saml');
const fs = require('fs');
const config = require('../../config/config');
const userService = require('../../services/userService');
const logger = require('../../utils/logger');
const auditService = require('../../services/auditService');

/**
 * SAML 2.0 Single Sign-On Authentication Strategy
 */
const createSamlStrategy = () => {
  // Load SAML certificate if path is provided
  let cert = config.saml.cert;
  if (!cert && config.saml.certPath) {
    try {
      cert = fs.readFileSync(config.saml.certPath, 'utf8');
    } catch (error) {
      logger.error('Failed to load SAML certificate:', error);
    }
  }

  const options = {
    entryPoint: config.saml.entryPoint,
    issuer: config.saml.issuer,
    callbackUrl: config.saml.callbackUrl,
    cert: cert,
    signatureAlgorithm: config.saml.signatureAlgorithm || 'sha256',
    digestAlgorithm: config.saml.digestAlgorithm || 'sha256',
    acceptedClockSkewMs: 5000, // 5 seconds clock skew tolerance
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    passReqToCallback: true
  };

  return new SamlStrategy(options, async (req, profile, done) => {
    try {
      logger.debug('SAML authentication attempt', {
        nameId: profile.nameID,
        nameIdFormat: profile.nameIDFormat,
        sessionIndex: profile.sessionIndex,
        ip: req.ip
      });

      // Validate SAML profile
      if (!profile.nameID) {
        logger.warn('Invalid SAML profile - missing nameID', {
          profile: profile,
          ip: req.ip
        });

        await auditService.log('saml_auth_failed', {
          reason: 'missing_name_id',
          profile: profile,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Invalid SAML response - missing nameID' 
        });
      }

      // Extract user information from SAML attributes
      const userInfo = extractUserInfo(profile);
      
      if (!userInfo.email) {
        logger.warn('SAML profile missing email', {
          nameId: profile.nameID,
          attributes: profile.attributes,
          ip: req.ip
        });

        await auditService.log('saml_auth_failed', {
          reason: 'missing_email',
          nameId: profile.nameID,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Email address is required for SAML authentication' 
        });
      }

      // Create or update user from SAML
      const user = await createOrUpdateSamlUser(userInfo, profile);

      if (!user) {
        logger.error('Failed to create/update SAML user', {
          nameId: profile.nameID,
          email: userInfo.email,
          ip: req.ip
        });

        await auditService.log('saml_auth_failed', {
          reason: 'user_creation_failed',
          nameId: profile.nameID,
          email: userInfo.email,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Failed to create or update user account' 
        });
      }

      // Check if account is active
      if (user.status !== 'active') {
        logger.warn('SAML authentication for inactive account', {
          userId: user._id,
          status: user.status,
          nameId: profile.nameID,
          ip: req.ip
        });

        await auditService.log('saml_auth_failed', {
          userId: user._id,
          reason: 'account_inactive',
          status: user.status,
          nameId: profile.nameID,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Account is not active' 
        });
      }

      // Check if account is locked
      if (user.isLocked) {
        logger.warn('SAML authentication for locked account', {
          userId: user._id,
          lockUntil: user.lockUntil,
          nameId: profile.nameID,
          ip: req.ip
        });

        await auditService.log('saml_auth_failed', {
          userId: user._id,
          reason: 'account_locked',
          lockUntil: user.lockUntil,
          nameId: profile.nameID,
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
        provider: 'saml',
        timestamp: new Date()
      };

      // Add session to user
      if (req.session) {
        await user.addSession(req.session.id, deviceInfo);
      }

      // Log successful SAML authentication
      await auditService.log('saml_auth_success', {
        userId: user._id,
        email: user.email,
        nameId: profile.nameID,
        sessionIndex: profile.sessionIndex,
        isNewUser: user.createdAt > new Date(Date.now() - 60000),
        deviceInfo
      });

      logger.info('SAML authentication successful', {
        userId: user._id,
        email: user.email,
        nameId: profile.nameID,
        ip: req.ip
      });

      // Attach SAML metadata
      user.authMethod = 'saml';
      user.authTimestamp = new Date();
      user.samlProfile = {
        nameID: profile.nameID,
        nameIDFormat: profile.nameIDFormat,
        sessionIndex: profile.sessionIndex,
        attributes: profile.attributes
      };

      return done(null, user);
    } catch (error) {
      logger.error('SAML strategy error:', error);

      await auditService.log('saml_auth_error', {
        error: error.message,
        nameId: profile?.nameID,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return done(error);
    }
  });
};

/**
 * Extract user information from SAML attributes
 */
function extractUserInfo(profile) {
  const attributes = profile.attributes || {};
  
  // Common SAML attribute mappings
  const attributeMappings = {
    email: ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', 'email', 'mail', 'emailAddress'],
    firstName: ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', 'firstName', 'givenName', 'fname'],
    lastName: ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname', 'lastName', 'surname', 'sn', 'lname'],
    displayName: ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', 'displayName', 'name', 'cn'],
    department: ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department', 'department', 'dept'],
    title: ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/title', 'title', 'jobTitle'],
    phone: ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone', 'phone', 'telephoneNumber'],
    groups: ['http://schemas.xmlsoap.org/claims/Group', 'groups', 'memberOf']
  };

  const userInfo = {};

  // Extract attributes using mappings
  Object.keys(attributeMappings).forEach(key => {
    const possibleNames = attributeMappings[key];
    for (const name of possibleNames) {
      if (attributes[name]) {
        userInfo[key] = Array.isArray(attributes[name]) ? attributes[name][0] : attributes[name];
        break;
      }
    }
  });

  // Fallback to nameID for email if not found in attributes
  if (!userInfo.email && profile.nameID) {
    // Check if nameID looks like an email
    if (profile.nameID.includes('@')) {
      userInfo.email = profile.nameID;
    }
  }

  return userInfo;
}

/**
 * Create or update user from SAML authentication
 */
async function createOrUpdateSamlUser(userInfo, profile) {
  try {
    // Check if user exists by email
    let user = await userService.getUserByEmail(userInfo.email);

    if (user) {
      // Update existing user with SAML data
      user.oauthProviders.saml = {
        nameId: profile.nameID,
        sessionIndex: profile.sessionIndex,
        attributes: profile.attributes
      };

      // Add SAML to auth providers if not already present
      if (!user.authProviders.includes('saml')) {
        user.authProviders.push('saml');
      }

      // Update profile information if not set
      if (!user.profile.firstName && userInfo.firstName) {
        user.profile.firstName = userInfo.firstName;
      }
      if (!user.profile.lastName && userInfo.lastName) {
        user.profile.lastName = userInfo.lastName;
      }
      if (!user.profile.displayName && userInfo.displayName) {
        user.profile.displayName = userInfo.displayName;
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      logger.info('SAML user updated', {
        userId: user._id,
        email: user.email,
        nameId: profile.nameID
      });
    } else {
      // Create new user
      const Role = require('../../models/Role');
      const defaultRole = await Role.findOne({ name: 'user' });

      user = await userService.createUser({
        email: userInfo.email,
        profile: {
          firstName: userInfo.firstName,
          lastName: userInfo.lastName,
          displayName: userInfo.displayName || `${userInfo.firstName} ${userInfo.lastName}`.trim()
        },
        authProviders: ['saml'],
        oauthProviders: {
          saml: {
            nameId: profile.nameID,
            sessionIndex: profile.sessionIndex,
            attributes: profile.attributes
          }
        },
        status: 'active',
        emailVerified: true, // Assume SAML emails are verified
        roles: defaultRole ? [defaultRole._id] : []
      });

      logger.info('SAML user created', {
        userId: user._id,
        email: user.email,
        nameId: profile.nameID
      });
    }

    return user;
  } catch (error) {
    logger.error('Error creating/updating SAML user:', error);
    throw error;
  }
}

module.exports = createSamlStrategy;

