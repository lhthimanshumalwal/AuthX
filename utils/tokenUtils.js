const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('../config/config');
const { logger } = require('./logger');

/**
 * Token Utilities - JWT and token management functions
 * Provides comprehensive token generation, validation, and management
 */
class TokenUtils {
  /**
   * Generate JWT access token
   * @param {Object} payload - Token payload
   * @param {Object} options - Token options
   * @returns {string} JWT token
   */
  generateAccessToken(payload, options = {}) {
    try {
      const tokenPayload = {
        sub: payload.userId || payload.id,
        email: payload.email,
        roles: payload.roles || [],
        permissions: payload.permissions || [],
        type: 'access',
        ...payload
      };

      const tokenOptions = {
        expiresIn: options.expiresIn || config.jwt.expiresIn,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: config.jwt.algorithm,
        ...options
      };

      return jwt.sign(tokenPayload, config.jwt.secret, tokenOptions);
    } catch (error) {
      logger.error('Failed to generate access token:', error);
      throw new Error('Token generation failed');
    }
  }

  /**
   * Generate JWT refresh token
   * @param {Object} payload - Token payload
   * @param {Object} options - Token options
   * @returns {string} JWT refresh token
   */
  generateRefreshToken(payload, options = {}) {
    try {
      const tokenPayload = {
        sub: payload.userId || payload.id,
        email: payload.email,
        type: 'refresh',
        tokenId: crypto.randomUUID(),
        ...payload
      };

      const tokenOptions = {
        expiresIn: options.expiresIn || config.jwt.refreshExpiresIn,
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: config.jwt.algorithm,
        ...options
      };

      return jwt.sign(tokenPayload, config.jwt.refreshSecret, tokenOptions);
    } catch (error) {
      logger.error('Failed to generate refresh token:', error);
      throw new Error('Refresh token generation failed');
    }
  }

  /**
   * Generate token pair (access + refresh)
   * @param {Object} payload - Token payload
   * @param {Object} options - Token options
   * @returns {Object} Token pair
   */
  generateTokenPair(payload, options = {}) {
    try {
      const accessToken = this.generateAccessToken(payload, options.access);
      const refreshToken = this.generateRefreshToken(payload, options.refresh);

      return {
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresIn: this.getTokenExpiration(config.jwt.expiresIn),
        refreshExpiresIn: this.getTokenExpiration(config.jwt.refreshExpiresIn)
      };
    } catch (error) {
      logger.error('Failed to generate token pair:', error);
      throw new Error('Token pair generation failed');
    }
  }

  /**
   * Verify JWT access token
   * @param {string} token - JWT token
   * @param {Object} options - Verification options
   * @returns {Object} Decoded token payload
   */
  verifyAccessToken(token, options = {}) {
    try {
      const verifyOptions = {
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithms: [config.jwt.algorithm],
        ...options
      };

      const decoded = jwt.verify(token, config.jwt.secret, verifyOptions);
      
      // Validate token type
      if (decoded.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Token expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid token');
      } else if (error.name === 'NotBeforeError') {
        throw new Error('Token not active');
      }
      
      logger.error('Token verification failed:', error);
      throw new Error('Token verification failed');
    }
  }

  /**
   * Verify JWT refresh token
   * @param {string} token - JWT refresh token
   * @param {Object} options - Verification options
   * @returns {Object} Decoded token payload
   */
  verifyRefreshToken(token, options = {}) {
    try {
      const verifyOptions = {
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithms: [config.jwt.algorithm],
        ...options
      };

      const decoded = jwt.verify(token, config.jwt.refreshSecret, verifyOptions);
      
      // Validate token type
      if (decoded.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Refresh token expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid refresh token');
      } else if (error.name === 'NotBeforeError') {
        throw new Error('Refresh token not active');
      }
      
      logger.error('Refresh token verification failed:', error);
      throw new Error('Refresh token verification failed');
    }
  }

  /**
   * Decode token without verification (for inspection)
   * @param {string} token - JWT token
   * @returns {Object} Decoded token
   */
  decodeToken(token) {
    try {
      return jwt.decode(token, { complete: true });
    } catch (error) {
      logger.error('Token decode failed:', error);
      return null;
    }
  }

  /**
   * Check if token is expired
   * @param {string} token - JWT token
   * @returns {boolean} True if expired
   */
  isTokenExpired(token) {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded || !decoded.payload.exp) {
        return true;
      }
      
      return Date.now() >= decoded.payload.exp * 1000;
    } catch (error) {
      return true;
    }
  }

  /**
   * Get token expiration time
   * @param {string} token - JWT token
   * @returns {Date|null} Expiration date or null
   */
  getTokenExpiration(token) {
    try {
      if (typeof token === 'string' && token.includes('h')) {
        // Handle time strings like '1h', '24h'
        const hours = parseInt(token.replace('h', ''));
        return new Date(Date.now() + hours * 60 * 60 * 1000);
      } else if (typeof token === 'string' && token.includes('d')) {
        // Handle time strings like '7d', '30d'
        const days = parseInt(token.replace('d', ''));
        return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
      } else if (typeof token === 'string' && token.includes('m')) {
        // Handle time strings like '15m', '30m'
        const minutes = parseInt(token.replace('m', ''));
        return new Date(Date.now() + minutes * 60 * 1000);
      } else {
        // Assume it's a JWT token
        const decoded = this.decodeToken(token);
        if (decoded && decoded.payload.exp) {
          return new Date(decoded.payload.exp * 1000);
        }
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Generate magic link token
   * @param {Object} payload - Token payload
   * @param {Object} options - Token options
   * @returns {string} Magic link token
   */
  generateMagicLinkToken(payload, options = {}) {
    try {
      const tokenPayload = {
        sub: payload.userId || payload.id,
        email: payload.email,
        type: 'magic-link',
        purpose: payload.purpose || 'login',
        tokenId: crypto.randomUUID(),
        ...payload
      };

      const tokenOptions = {
        expiresIn: options.expiresIn || '10m', // 10 minutes default
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: config.jwt.algorithm,
        ...options
      };

      return jwt.sign(tokenPayload, config.jwt.secret, tokenOptions);
    } catch (error) {
      logger.error('Failed to generate magic link token:', error);
      throw new Error('Magic link token generation failed');
    }
  }

  /**
   * Generate OTP token
   * @param {Object} payload - Token payload
   * @param {Object} options - Token options
   * @returns {Object} OTP token and code
   */
  generateOTPToken(payload, options = {}) {
    try {
      const otpCode = this.generateOTPCode(options.length || 6);
      
      const tokenPayload = {
        sub: payload.userId || payload.id,
        email: payload.email,
        type: 'otp',
        code: otpCode,
        purpose: payload.purpose || 'verification',
        tokenId: crypto.randomUUID(),
        ...payload
      };

      const tokenOptions = {
        expiresIn: options.expiresIn || '5m', // 5 minutes default
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: config.jwt.algorithm,
        ...options
      };

      const token = jwt.sign(tokenPayload, config.jwt.secret, tokenOptions);

      return {
        token,
        code: otpCode,
        expiresAt: this.getTokenExpiration(tokenOptions.expiresIn)
      };
    } catch (error) {
      logger.error('Failed to generate OTP token:', error);
      throw new Error('OTP token generation failed');
    }
  }

  /**
   * Generate OTP code
   * @param {number} length - Code length
   * @returns {string} OTP code
   */
  generateOTPCode(length = 6) {
    const digits = '0123456789';
    let code = '';
    
    for (let i = 0; i < length; i++) {
      code += digits[Math.floor(Math.random() * digits.length)];
    }
    
    return code;
  }

  /**
   * Verify OTP token and code
   * @param {string} token - OTP token
   * @param {string} code - OTP code
   * @returns {Object} Verification result
   */
  verifyOTPToken(token, code) {
    try {
      const decoded = this.verifyAccessToken(token);
      
      if (decoded.type !== 'otp') {
        throw new Error('Invalid token type');
      }

      if (decoded.code !== code) {
        throw new Error('Invalid OTP code');
      }

      return decoded;
    } catch (error) {
      logger.error('OTP verification failed:', error);
      throw error;
    }
  }

  /**
   * Generate API key
   * @param {Object} payload - Key payload
   * @param {Object} options - Key options
   * @returns {Object} API key and metadata
   */
  generateAPIKey(payload, options = {}) {
    try {
      const keyId = crypto.randomUUID();
      const keySecret = crypto.randomBytes(32).toString('hex');
      
      const tokenPayload = {
        sub: payload.userId || payload.id,
        type: 'api-key',
        keyId: keyId,
        name: payload.name || 'API Key',
        scopes: payload.scopes || [],
        ...payload
      };

      const tokenOptions = {
        expiresIn: options.expiresIn || '1y', // 1 year default
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
        algorithm: config.jwt.algorithm,
        ...options
      };

      const token = jwt.sign(tokenPayload, keySecret, tokenOptions);

      return {
        keyId,
        token,
        secret: keySecret,
        name: tokenPayload.name,
        scopes: tokenPayload.scopes,
        expiresAt: this.getTokenExpiration(tokenOptions.expiresIn)
      };
    } catch (error) {
      logger.error('Failed to generate API key:', error);
      throw new Error('API key generation failed');
    }
  }

  /**
   * Generate secure random token
   * @param {number} length - Token length in bytes
   * @returns {string} Random token
   */
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate CSRF token
   * @returns {string} CSRF token
   */
  generateCSRFToken() {
    return crypto.randomBytes(32).toString('base64url');
  }

  /**
   * Hash token for storage
   * @param {string} token - Token to hash
   * @returns {string} Hashed token
   */
  hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Compare token with hash
   * @param {string} token - Plain token
   * @param {string} hash - Hashed token
   * @returns {boolean} Match result
   */
  compareTokenHash(token, hash) {
    const tokenHash = this.hashToken(token);
    return crypto.timingSafeEqual(Buffer.from(tokenHash), Buffer.from(hash));
  }

  /**
   * Extract token from Authorization header
   * @param {string} authHeader - Authorization header value
   * @returns {string|null} Token or null
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
   * Get token metadata
   * @param {string} token - JWT token
   * @returns {Object} Token metadata
   */
  getTokenMetadata(token) {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded) {
        return null;
      }

      const { header, payload } = decoded;
      
      return {
        algorithm: header.alg,
        type: payload.type,
        subject: payload.sub,
        issuer: payload.iss,
        audience: payload.aud,
        issuedAt: payload.iat ? new Date(payload.iat * 1000) : null,
        expiresAt: payload.exp ? new Date(payload.exp * 1000) : null,
        notBefore: payload.nbf ? new Date(payload.nbf * 1000) : null,
        isExpired: this.isTokenExpired(token)
      };
    } catch (error) {
      logger.error('Failed to get token metadata:', error);
      return null;
    }
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @param {Object} options - Refresh options
   * @returns {Object} New token pair
   */
  refreshAccessToken(refreshToken, options = {}) {
    try {
      // Verify refresh token
      const decoded = this.verifyRefreshToken(refreshToken);
      
      // Generate new token pair
      const payload = {
        userId: decoded.sub,
        email: decoded.email,
        roles: decoded.roles,
        permissions: decoded.permissions
      };

      return this.generateTokenPair(payload, options);
    } catch (error) {
      logger.error('Failed to refresh access token:', error);
      throw error;
    }
  }
}

module.exports = new TokenUtils();

