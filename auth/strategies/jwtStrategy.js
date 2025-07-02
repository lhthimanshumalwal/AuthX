const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const config = require('../../config/config');
const userService = require('../../services/userService');
const tokenUtils = require('../../utils/tokenUtils');
const logger = require('../../utils/logger');
const auditService = require('../../services/auditService');

/**
 * JWT Authentication Strategy
 * Used for API authentication with Bearer tokens
 */
const createJwtStrategy = () => {
  const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: config.jwt.secret,
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
    algorithms: ['HS256'],
    passReqToCallback: true // Pass request to callback for additional context
  };

  return new JwtStrategy(options, async (req, payload, done) => {
    try {
      // Extract token from request for blacklist checking
      const token = tokenUtils.extractTokenFromHeader(req.headers.authorization);
      
      // Check if token is blacklisted
      if (token && tokenUtils.isTokenBlacklisted(token)) {
        logger.warn('Blacklisted JWT token used', {
          userId: payload.sub,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        await auditService.log('blacklisted_token_used', {
          userId: payload.sub,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          tokenType: 'access'
        });
        
        return done(null, false, { message: 'Token has been revoked' });
      }

      // Validate token payload
      if (!payload.sub || payload.type !== 'access') {
        logger.warn('Invalid JWT token payload', {
          payload: tokenUtils.maskSensitiveData(payload),
          ip: req.ip
        });
        
        return done(null, false, { message: 'Invalid token payload' });
      }

      // Get user from database
      const user = await userService.getUserById(payload.sub);
      
      if (!user) {
        logger.warn('JWT token for non-existent user', {
          userId: payload.sub,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        await auditService.log('jwt_auth_failed', {
          userId: payload.sub,
          reason: 'user_not_found',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        return done(null, false, { message: 'User not found' });
      }

      // Check if user account is active
      if (user.status !== 'active') {
        logger.warn('JWT token for inactive user', {
          userId: user._id,
          status: user.status,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        await auditService.log('jwt_auth_failed', {
          userId: user._id,
          reason: 'account_inactive',
          status: user.status,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        return done(null, false, { message: 'Account is not active' });
      }

      // Check if user is locked
      if (user.isLocked) {
        logger.warn('JWT token for locked user', {
          userId: user._id,
          lockUntil: user.lockUntil,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        await auditService.log('jwt_auth_failed', {
          userId: user._id,
          reason: 'account_locked',
          lockUntil: user.lockUntil,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        return done(null, false, { message: 'Account is temporarily locked' });
      }

      // Validate token claims against user data
      if (payload.email !== user.email) {
        logger.warn('JWT token email mismatch', {
          userId: user._id,
          tokenEmail: payload.email,
          userEmail: user.email,
          ip: req.ip
        });
        
        await auditService.log('jwt_auth_failed', {
          userId: user._id,
          reason: 'email_mismatch',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        return done(null, false, { message: 'Token claims do not match user data' });
      }

      // Check if email verification is required
      if (config.security.requireEmailVerification && !user.emailVerified) {
        logger.warn('JWT token for unverified user', {
          userId: user._id,
          emailVerified: user.emailVerified,
          ip: req.ip
        });
        
        return done(null, false, { 
          message: 'Email verification required',
          requiresEmailVerification: true 
        });
      }

      // Check if 2FA is required but not completed
      if (user.twoFactorAuth?.enabled && !payload.twoFactorVerified) {
        logger.info('JWT token requires 2FA verification', {
          userId: user._id,
          ip: req.ip
        });
        
        return done(null, false, { 
          message: 'Two-factor authentication required',
          requiresTwoFactor: true,
          userId: user._id
        });
      }

      // Update last activity (optional, can be expensive)
      if (config.features.trackLastActivity) {
        user.lastActivity = new Date();
        await user.save();
      }

      // Log successful authentication
      await auditService.log('jwt_auth_success', {
        userId: user._id,
        email: user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        tokenIssued: new Date(payload.iat * 1000),
        tokenExpires: new Date(payload.exp * 1000)
      });

      logger.debug('JWT authentication successful', {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });

      // Attach additional context to user object
      user.authMethod = 'jwt';
      user.tokenPayload = payload;
      user.authTimestamp = new Date();

      return done(null, user);
    } catch (error) {
      logger.error('JWT strategy error:', error);
      
      await auditService.log('jwt_auth_error', {
        error: error.message,
        stack: error.stack,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      return done(error);
    }
  });
};

module.exports = createJwtStrategy;

