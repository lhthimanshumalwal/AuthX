const { Strategy: GitHubStrategy } = require('passport-github');
const config = require('../../config/config');
const userService = require('../../services/userService');
const logger = require('../../utils/logger');
const auditService = require('../../services/auditService');

/**
 * GitHub OAuth Authentication Strategy
 */
const createGitHubStrategy = () => {
  const options = {
    clientID: config.oauth.github.clientID,
    clientSecret: config.oauth.github.clientSecret,
    callbackURL: config.oauth.github.callbackURL,
    scope: config.oauth.github.scope || ['user:email'],
    passReqToCallback: true
  };

  return new GitHubStrategy(options, async (req, accessToken, refreshToken, profile, done) => {
    try {
      logger.debug('GitHub OAuth authentication attempt', {
        profileId: profile.id,
        username: profile.username,
        email: profile.emails?.[0]?.value,
        ip: req.ip
      });

      // Validate profile data
      if (!profile.id || !profile.username) {
        logger.warn('Invalid GitHub profile data', {
          profileId: profile.id,
          username: profile.username,
          hasEmails: !!profile.emails?.length,
          ip: req.ip
        });

        await auditService.log('oauth_auth_failed', {
          provider: 'github',
          reason: 'invalid_profile_data',
          profileId: profile.id,
          username: profile.username,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return done(null, false, { 
          message: 'Invalid profile data from GitHub' 
        });
      }

      // GitHub might not provide email in profile if user's email is private
      let email = null;
      if (profile.emails && profile.emails.length > 0) {
        // Find primary email or first email
        const primaryEmail = profile.emails.find(e => e.primary) || profile.emails[0];
        email = primaryEmail.value;
      }

      // If no email in profile, we might need to fetch it via GitHub API
      if (!email) {
        logger.warn('No email provided by GitHub', {
          profileId: profile.id,
          username: profile.username,
          ip: req.ip
        });

        // In a production environment, you might want to make an API call to GitHub
        // to fetch the user's email addresses using the access token
        // For now, we'll create the user without email and let them add it later
      }

      // Create or update user
      const user = await userService.createOrUpdateOAuthUser('github', profile, accessToken);

      if (!user) {
        logger.error('Failed to create/update GitHub OAuth user', {
          profileId: profile.id,
          username: profile.username,
          email: email,
          ip: req.ip
        });

        await auditService.log('oauth_auth_failed', {
          provider: 'github',
          reason: 'user_creation_failed',
          profileId: profile.id,
          username: profile.username,
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
        logger.warn('GitHub OAuth for inactive account', {
          userId: user._id,
          status: user.status,
          username: profile.username,
          ip: req.ip
        });

        await auditService.log('oauth_auth_failed', {
          provider: 'github',
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
        logger.warn('GitHub OAuth for locked account', {
          userId: user._id,
          lockUntil: user.lockUntil,
          username: profile.username,
          ip: req.ip
        });

        await auditService.log('oauth_auth_failed', {
          provider: 'github',
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

      // Create device info
      const deviceInfo = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        provider: 'github',
        timestamp: new Date()
      };

      // Add session to user
      if (req.session) {
        await user.addSession(req.session.id, deviceInfo);
      }

      // Log successful OAuth authentication
      await auditService.log('oauth_auth_success', {
        provider: 'github',
        userId: user._id,
        email: user.email,
        profileId: profile.id,
        username: profile.username,
        isNewUser: user.createdAt > new Date(Date.now() - 60000), // Created in last minute
        deviceInfo
      });

      logger.info('GitHub OAuth authentication successful', {
        userId: user._id,
        email: user.email,
        profileId: profile.id,
        username: profile.username,
        ip: req.ip
      });

      // Attach OAuth metadata
      user.authMethod = 'github';
      user.authTimestamp = new Date();
      user.oauthProfile = {
        provider: 'github',
        id: profile.id,
        username: profile.username,
        accessToken: accessToken,
        refreshToken: refreshToken,
        profile: {
          displayName: profile.displayName,
          username: profile.username,
          profileUrl: profile.profileUrl,
          photos: profile.photos,
          emails: profile.emails,
          company: profile._json?.company,
          blog: profile._json?.blog,
          location: profile._json?.location,
          bio: profile._json?.bio,
          publicRepos: profile._json?.public_repos,
          followers: profile._json?.followers,
          following: profile._json?.following
        }
      };

      // Store tokens securely (optional - consider encryption)
      if (config.oauth.storeTokens) {
        user.oauthProviders.github.accessToken = accessToken;
        user.oauthProviders.github.refreshToken = refreshToken;
        user.oauthProviders.github.tokenExpiry = new Date(Date.now() + 3600000); // 1 hour
        await user.save();
      }

      return done(null, user);
    } catch (error) {
      logger.error('GitHub OAuth strategy error:', error);

      await auditService.log('oauth_auth_error', {
        provider: 'github',
        error: error.message,
        profileId: profile?.id,
        username: profile?.username,
        email: profile?.emails?.[0]?.value,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return done(error);
    }
  });
};

module.exports = createGitHubStrategy;

