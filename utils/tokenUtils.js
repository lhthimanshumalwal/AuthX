const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config/config');
const logger = require('./logger');

class TokenUtils {
  constructor() {
    this.blacklistedTokens = new Set(); // In production, use Redis
  }

  /**
   * Generate JWT access token
   */
  generateAccessToken(user) {
    try {
      const payload = {
        sub: user._id.toString(),
        email: user.email,
        username: user.username,
        roles: user.roles?.map(role => role.name || role) || [],
        permissions: user.permissions || [],
        status: user.status,
        emailVerified: user.emailVerified,
        twoFactorEnabled: user.twoFactorAuth?.enabled || false,
        type: 'access'
      };

      const options = {
        expiresIn: config.jwt.expiresIn,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: 'HS256'
      };

      const token = jwt.sign(payload, config.jwt.secret, options);
      
      logger.debug(`Access token generated for user: ${user.email}`);
      return token;
    } catch (error) {
      logger.error('Error generating access token:', error);
      throw new Error('Failed to generate access token');
    }
  }

  /**
   * Generate JWT refresh token
   */
  generateRefreshToken(user) {
    try {
      const payload = {
        sub: user._id.toString(),
        email: user.email,
        type: 'refresh',
        tokenId: crypto.randomUUID()
      };

      const options = {
        expiresIn: config.jwt.refreshExpiresIn,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: 'HS256'
      };

      const token = jwt.sign(payload, config.jwt.refreshSecret, options);
      
      logger.debug(`Refresh token generated for user: ${user.email}`);
      return token;
    } catch (error) {
      logger.error('Error generating refresh token:', error);
      throw new Error('Failed to generate refresh token');
    }
  }

  /**
   * Generate token pair (access + refresh)
   */
  generateTokenPair(user) {
    return {
      accessToken: this.generateAccessToken(user),
      refreshToken: this.generateRefreshToken(user),
      tokenType: 'Bearer',
      expiresIn: this.getTokenExpirySeconds(config.jwt.expiresIn)
    };
  }

  /**
   * Verify JWT access token
   */
  verifyAccessToken(token) {
    try {
      // Check if token is blacklisted
      if (this.isTokenBlacklisted(token)) {
        throw new Error('Token has been revoked');
      }

      const options = {
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithms: ['HS256']
      };

      const decoded = jwt.verify(token, config.jwt.secret, options);
      
      // Verify token type
      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Token has expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid token');
      } else if (error.name === 'NotBeforeError') {
        throw new Error('Token not active yet');
      }
      
      logger.error('Error verifying access token:', error);
      throw error;
    }
  }

  /**
   * Verify JWT refresh token
   */
  verifyRefreshToken(token) {
    try {
      // Check if token is blacklisted
      if (this.isTokenBlacklisted(token)) {
        throw new Error('Token has been revoked');
      }

      const options = {
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithms: ['HS256']
      };

      const decoded = jwt.verify(token, config.jwt.refreshSecret, options);
      
      // Verify token type
      if (decoded.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Refresh token has expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid refresh token');
      }
      
      logger.error('Error verifying refresh token:', error);
      throw error;
    }
  }

  /**
   * Decode token without verification (for inspection)
   */
  decodeToken(token) {
    try {
      return jwt.decode(token, { complete: true });
    } catch (error) {
      logger.error('Error decoding token:', error);
      return null;
    }
  }

  /**
   * Get token expiry time in seconds
   */
  getTokenExpirySeconds(expiresIn) {
    if (typeof expiresIn === 'string') {
      const unit = expiresIn.slice(-1);
      const value = parseInt(expiresIn.slice(0, -1));
      
      switch (unit) {
        case 's': return value;
        case 'm': return value * 60;
        case 'h': return value * 60 * 60;
        case 'd': return value * 24 * 60 * 60;
        default: return 3600; // 1 hour default
      }
    }
    
    return expiresIn || 3600;
  }

  /**
   * Extract token from Authorization header
   */
  extractTokenFromHeader(authHeader) {
    if (!authHeader) {
      return null;
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return null;
    }

    return parts[1];
  }

  /**
   * Blacklist a token
   */
  blacklistToken(token) {
    try {
      const decoded = this.decodeToken(token);
      if (decoded && decoded.payload) {
        // Store token hash to save memory
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        this.blacklistedTokens.add(tokenHash);
        
        // In production, store in Redis with expiry
        // redis.setex(`blacklist:${tokenHash}`, decoded.payload.exp - Math.floor(Date.now() / 1000), '1');
        
        logger.debug('Token blacklisted successfully');
        return true;
      }
      return false;
    } catch (error) {
      logger.error('Error blacklisting token:', error);
      return false;
    }
  }

  /**
   * Check if token is blacklisted
   */
  isTokenBlacklisted(token) {
    try {
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      return this.blacklistedTokens.has(tokenHash);
      
      // In production, check Redis
      // return await redis.exists(`blacklist:${tokenHash}`);
    } catch (error) {
      logger.error('Error checking token blacklist:', error);
      return false;
    }
  }

  /**
   * Generate secure random token
   */
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate API key
   */
  generateApiKey(prefix = 'authx') {
    const timestamp = Date.now().toString(36);
    const randomPart = crypto.randomBytes(16).toString('hex');
    return `${prefix}_${timestamp}_${randomPart}`;
  }

  /**
   * Hash token for storage
   */
  hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Generate magic link token
   */
  generateMagicLinkToken(email) {
    try {
      const payload = {
        email: email.toLowerCase(),
        type: 'magic-link',
        tokenId: crypto.randomUUID(),
        iat: Math.floor(Date.now() / 1000)
      };

      const options = {
        expiresIn: '15m', // Magic links expire quickly
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: 'HS256'
      };

      const token = jwt.sign(payload, config.jwt.secret, options);
      
      logger.debug(`Magic link token generated for: ${email}`);
      return token;
    } catch (error) {
      logger.error('Error generating magic link token:', error);
      throw new Error('Failed to generate magic link token');
    }
  }

  /**
   * Verify magic link token
   */
  verifyMagicLinkToken(token) {
    try {
      const options = {
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithms: ['HS256']
      };

      const decoded = jwt.verify(token, config.jwt.secret, options);
      
      // Verify token type
      if (decoded.type !== 'magic-link') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Magic link has expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid magic link');
      }
      
      logger.error('Error verifying magic link token:', error);
      throw error;
    }
  }

  /**
   * Generate email verification token
   */
  generateEmailVerificationToken(email, userId) {
    try {
      const payload = {
        email: email.toLowerCase(),
        userId: userId.toString(),
        type: 'email-verification',
        tokenId: crypto.randomUUID()
      };

      const options = {
        expiresIn: '24h',
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: 'HS256'
      };

      const token = jwt.sign(payload, config.jwt.secret, options);
      
      logger.debug(`Email verification token generated for: ${email}`);
      return token;
    } catch (error) {
      logger.error('Error generating email verification token:', error);
      throw new Error('Failed to generate email verification token');
    }
  }

  /**
   * Generate password reset token
   */
  generatePasswordResetToken(email, userId) {
    try {
      const payload = {
        email: email.toLowerCase(),
        userId: userId.toString(),
        type: 'password-reset',
        tokenId: crypto.randomUUID()
      };

      const options = {
        expiresIn: '1h',
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: 'HS256'
      };

      const token = jwt.sign(payload, config.jwt.secret, options);
      
      logger.debug(`Password reset token generated for: ${email}`);
      return token;
    } catch (error) {
      logger.error('Error generating password reset token:', error);
      throw new Error('Failed to generate password reset token');
    }
  }

  /**
   * Clean up expired blacklisted tokens
   */
  cleanupBlacklistedTokens() {
    // In production, this would be handled by Redis TTL
    // For in-memory implementation, we'd need to track expiry times
    logger.debug('Blacklisted tokens cleanup completed');
  }

  /**
   * Get token information
   */
  getTokenInfo(token) {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded) {
        return null;
      }

      const now = Math.floor(Date.now() / 1000);
      const payload = decoded.payload;

      return {
        valid: payload.exp > now,
        expired: payload.exp <= now,
        expiresAt: new Date(payload.exp * 1000),
        issuedAt: new Date(payload.iat * 1000),
        issuer: payload.iss,
        audience: payload.aud,
        subject: payload.sub,
        type: payload.type,
        timeUntilExpiry: Math.max(0, payload.exp - now)
      };
    } catch (error) {
      logger.error('Error getting token info:', error);
      return null;
    }
  }
}

module.exports = new TokenUtils();

