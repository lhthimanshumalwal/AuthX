const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const config = require('../../config/config');
const userService = require('../../services/userService');
const logger = require('../../utils/logger');
const auditService = require('../../services/auditService');

/**
 * Google OAuth 2.0 Authentication Strategy
 */
const createGoogleStrategy = () => {
  const options = {
    clientID: config.oauth.google.clientID,
    clientSecret: config.oauth.google.clientSecret,
    callbackURL: config.oauth.google.callbackURL,
    scope: config.oauth.google.scope || ['profile', 'email'],
    passReqToCallback: true
  };

  return new GoogleStrategy(options, async (req, accessToken, refreshToken, profile, done) => {
    try {
      logger.debug('Google OAuth authentication attempt', {
        profileId: profile.id,
        email: profile.emails?.[0]?.value,
        ip: req.ip
      });

      // Validate profile data
      if (!profile.id || !profile.emails || profile.emails.length === 0) {
        logger.warn('Invalid Google profile data', {
          profileId: profile.id,
          hasEmails: !!profile.emails?.length,
          ip: req.ip
        });

        await auditService.log('oauth_auth_failed', {
          provider: 'google',
          reason: 'invalid_profile_data',
          profileId: profile.id,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Invalid profile data from Google' 
        });
      }

      const email = profile.emails[0].value;
      const isVerified = profile.emails[0].verified;

      // Create or update user
      const user = await userService.createOrUpdateOAuthUser('google', profile, accessToken);

      if (!user) {
        logger.error('Failed to create/update Google OAuth user', {
          profileId: profile.id,
          email: email,
          ip: req.ip
        });

        await auditService.log('oauth_auth_failed', {
          provider: 'google',
          reason: 'user_creation_failed',
          profileId: profile.id,
          email: email,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Failed to create or update user account' 
        });
      }

      // Check if account is active
      if (user.status !== 'active') {
        logger.warn('Google OAuth for inactive account', {
          userId: user._id,
          status: user.status,
          email: email,
          ip: req.ip
        });

        await auditService.log('oauth_auth_failed', {
          provider: 'google',
          userId: user._id,
          reason: 'account_inactive',
          status: user.status,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Account is not active' 
        });
      }

      // Check if account is locked
      if (user.isLocked) {
        logger.warn('Google OAuth for locked account', {
          userId: user._id,
          lockUntil: user.lockUntil,
          email: email,
          ip: req.ip
        });

        await auditService.log('oauth_auth_failed', {
          provider: 'google',
          userId: user._id,
          reason: 'account_locked',
          lockUntil: user.lockUntil,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Account is temporarily locked' 
        });
      }

      // Update email verification status if Google email is verified
      if (isVerified && !user.emailVerified) {
        user.emailVerified = true;
        await user.save();
        
        logger.info('Email verified via Google OAuth', {
          userId: user._id,
          email: email
        });
      }

      // Create device info
      const deviceInfo = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        provider: 'google',
        timestamp: new Date()
      };

      // Add session to user
      if (req.session) {
        await user.addSession(req.session.id, deviceInfo);
      }

      // Log successful OAuth authentication
      await auditService.log('oauth_auth_success', {
        provider: 'google',
        userId: user._id,
        email: user.email,
        profileId: profile.id,
        isNewUser: user.createdAt > new Date(Date.now() - 60000), // Created in last minute
        deviceInfo
      });

      logger.info('Google OAuth authentication successful', {
        userId: user._id,
        email: user.email,
        profileId: profile.id,
        ip: req.ip
      });

      // Attach OAuth metadata
      user.authMethod = 'google';
      user.authTimestamp = new Date();
      user.oauthProfile = {
        provider: 'google',
        id: profile.id,
        accessToken: accessToken, // Be careful with token storage
        refreshToken: refreshToken,
        profile: {
          displayName: profile.displayName,
          name: profile.name,
          photos: profile.photos,
          emails: profile.emails
        }
      };

      // Store tokens securely (optional - consider encryption)
      if (config.oauth.storeTokens) {
        user.oauthProviders.google.accessToken = accessToken;
        user.oauthProviders.google.refreshToken = refreshToken;
        user.oauthProviders.google.tokenExpiry = new Date(Date.now() + 3600000); // 1 hour
        await user.save();
      }

      return done(null, user);
    } catch (error) {
      logger.error('Google OAuth strategy error:', error);

      await auditService.log('oauth_auth_error', {
        provider: 'google',
        error: error.message,
        profileId: profile?.id,
        email: profile?.emails?.[0]?.value,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return done(error);
    }
  });
};

module.exports = createGoogleStrategy;

