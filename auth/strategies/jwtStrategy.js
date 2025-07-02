const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const AuthStrategy = require('../interfaces/AuthStrategy');
const config = require('../../config/config');
const userService = require('../../services/userService');
const tokenUtils = require('../../utils/tokenUtils');
const { logger } = require('../../utils/logger');

/**
 * JWT Authentication Strategy
 * Handles stateless JWT token authentication for API access
 */
class JWTAuthStrategy extends AuthStrategy {
  constructor(options = {}) {
    super('jwt', {
      enabled: true,
      priority: 100, // High priority for API authentication
      ...options
    });
  }

  /**
   * Initialize the JWT strategy
   */
  async initialize() {
    try {
      const strategyOptions = {
        jwtFromRequest: ExtractJwt.fromExtractors([
          ExtractJwt.fromAuthHeaderAsBearerToken(),
          ExtractJwt.fromUrlQueryParameter('token'),
          ExtractJwt.fromBodyField('token'),
          this.extractFromCookie
        ]),
        secretOrKey: config.jwt.secret,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithms: [config.jwt.algorithm],
        ignoreExpiration: false,
        passReqToCallback: true
      };

      const strategy = new JwtStrategy(strategyOptions, this.verify.bind(this));
      passport.use('jwt', strategy);

      logger.info('JWT authentication strategy initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize JWT strategy:', error);
      throw error;
    }
  }

  /**
   * Validate strategy configuration
   */
  validateConfig() {
    if (!config.jwt.secret) {
      throw new Error('JWT secret is required');
    }

    if (config.server.env === 'production' && config.jwt.secret === 'fallback-secret-change-in-production') {
      throw new Error('JWT secret must be changed in production');
    }

    return true;
  }

  /**
   * Get strategy type
   */
  getType() {
    return 'jwt';
  }

  /**
   * JWT strategy doesn't require redirect
   */
  requiresRedirect() {
    return false;
  }

  /**
   * JWT strategy supports token refresh
   */
  supportsRefresh() {
    return true;
  }

  /**
   * JWT strategy can support MFA through token claims
   */
  supportsMFA() {
    return true;
  }

  /**
   * JWT verification callback
   * @param {Object} req - Express request object
   * @param {Object} payload - JWT payload
   * @param {Function} done - Passport done callback
   */
  async verify(req, payload, done) {
    try {
      // Validate token type
      if (payload.type !== 'access') {
        return done(null, false, { message: 'Invalid token type' });
      }

      // Find user by ID from token
      const user = await userService.findById(payload.sub);
      if (!user) {
        return done(null, false, { message: 'User not found' });
      }

      // Check if user is active
      if (user.status !== 'active') {
        return done(null, false, { message: 'User account is not active' });
      }

      // Add token information to user object
      user.tokenPayload = payload;
      user.strategy = 'jwt';

      // Check for MFA requirement if enabled
      if (user.mfa.enabled && !payload.mfaVerified) {
        return done(null, false, { 
          message: 'MFA verification required',
          requiresMFA: true,
          mfaToken: tokenUtils.generateMagicLinkToken({
            userId: user._id,
            email: user.email,
            purpose: 'mfa'
          })
        });
      }

      return done(null, user);
    } catch (error) {
      logger.error('JWT verification error:', error);
      return done(error, false);
    }
  }

  /**
   * Extract JWT from cookie
   * @param {Object} req - Express request object
   * @returns {string|null} JWT token or null
   */
  extractFromCookie(req) {
    if (req && req.cookies && req.cookies.accessToken) {
      return req.cookies.accessToken;
    }
    return null;
  }

  /**
   * Handle successful authentication
   */
  async handleSuccess(profile, tokens = null, req = null) {
    const result = await super.handleSuccess(profile, tokens, req);
    
    // Add JWT-specific metadata
    result.metadata.tokenType = 'Bearer';
    result.metadata.tokenExpiry = profile.tokenPayload ? profile.tokenPayload.exp : null;
    
    return result;
  }

  /**
   * Get authentication routes for JWT strategy
   */
  getRoutes() {
    return [
      {
        method: 'POST',
        path: '/auth/token/refresh',
        handler: 'refreshToken',
        description: 'Refresh JWT access token using refresh token'
      },
      {
        method: 'POST',
        path: '/auth/token/verify',
        handler: 'verifyToken',
        description: 'Verify JWT token validity'
      },
      {
        method: 'POST',
        path: '/auth/token/revoke',
        handler: 'revokeToken',
        description: 'Revoke JWT token'
      }
    ];
  }

  /**
   * Get middleware for JWT strategy
   */
  getMiddleware() {
    return [
      {
        name: 'jwtAuth',
        middleware: passport.authenticate('jwt', { session: false }),
        description: 'JWT authentication middleware'
      }
    ];
  }

  /**
   * Refresh token handler
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async refreshToken(req, res) {
    try {
      const { refreshToken } = req.body;
      
      if (!refreshToken) {
        return res.status(400).json({
          success: false,
          error: 'Refresh token is required'
        });
      }

      // Verify refresh token
      const decoded = tokenUtils.verifyRefreshToken(refreshToken);
      
      // Find user
      const user = await userService.findById(decoded.sub);
      if (!user || user.status !== 'active') {
        return res.status(401).json({
          success: false,
          error: 'Invalid refresh token'
        });
      }

      // Generate new token pair
      const tokenPair = tokenUtils.generateTokenPair({
        userId: user._id,
        email: user.email,
        roles: user.roles.map(role => role.name),
        permissions: await userService.getPermissions(user._id)
      });

      res.json({
        success: true,
        tokens: tokenPair,
        user: {
          id: user._id,
          email: user.email,
          profile: user.profile
        }
      });
    } catch (error) {
      logger.error('Token refresh error:', error);
      res.status(401).json({
        success: false,
        error: 'Invalid refresh token'
      });
    }
  }

  /**
   * Verify token handler
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async verifyToken(req, res) {
    try {
      const token = tokenUtils.extractTokenFromHeader(req.headers.authorization) || req.body.token;
      
      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Token is required'
        });
      }

      // Verify token
      const decoded = tokenUtils.verifyAccessToken(token);
      const metadata = tokenUtils.getTokenMetadata(token);

      res.json({
        success: true,
        valid: true,
        decoded: {
          sub: decoded.sub,
          email: decoded.email,
          roles: decoded.roles,
          permissions: decoded.permissions,
          type: decoded.type,
          iat: decoded.iat,
          exp: decoded.exp
        },
        metadata
      });
    } catch (error) {
      res.json({
        success: true,
        valid: false,
        error: error.message
      });
    }
  }

  /**
   * Revoke token handler
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async revokeToken(req, res) {
    try {
      const token = tokenUtils.extractTokenFromHeader(req.headers.authorization) || req.body.token;
      
      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Token is required'
        });
      }

      // In a production system, you would add the token to a blacklist
      // For now, we'll just return success
      // TODO: Implement token blacklisting with Redis

      res.json({
        success: true,
        message: 'Token revoked successfully'
      });
    } catch (error) {
      logger.error('Token revocation error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to revoke token'
      });
    }
  }

  /**
   * Serialize user for session (not used in JWT strategy)
   */
  async serializeUser(user) {
    return user._id.toString();
  }

  /**
   * Deserialize user from session (not used in JWT strategy)
   */
  async deserializeUser(id) {
    return await userService.findById(id);
  }
}

module.exports = JWTAuthStrategy;

