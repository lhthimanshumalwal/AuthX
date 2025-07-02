const crypto = require('crypto');
const bcrypt = require('bcrypt');
const config = require('../config/config');
const logger = require('./logger');

class CryptoUtils {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32;
    this.ivLength = 16;
    this.tagLength = 16;
  }

  /**
   * Generate a secure random string
   */
  generateSecureRandom(length = 32, encoding = 'hex') {
    try {
      return crypto.randomBytes(length).toString(encoding);
    } catch (error) {
      logger.error('Error generating secure random:', error);
      throw new Error('Failed to generate secure random string');
    }
  }

  /**
   * Generate a UUID v4
   */
  generateUUID() {
    return crypto.randomUUID();
  }

  /**
   * Hash a password using bcrypt
   */
  async hashPassword(password) {
    try {
      const saltRounds = config.security.bcryptRounds || 12;
      return await bcrypt.hash(password, saltRounds);
    } catch (error) {
      logger.error('Error hashing password:', error);
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Compare password with hash
   */
  async comparePassword(password, hash) {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      logger.error('Error comparing password:', error);
      throw new Error('Failed to compare password');
    }
  }

  /**
   * Generate a cryptographic hash
   */
  generateHash(data, algorithm = 'sha256', encoding = 'hex') {
    try {
      return crypto.createHash(algorithm).update(data).digest(encoding);
    } catch (error) {
      logger.error('Error generating hash:', error);
      throw new Error('Failed to generate hash');
    }
  }

  /**
   * Generate HMAC
   */
  generateHMAC(data, secret, algorithm = 'sha256', encoding = 'hex') {
    try {
      return crypto.createHmac(algorithm, secret).update(data).digest(encoding);
    } catch (error) {
      logger.error('Error generating HMAC:', error);
      throw new Error('Failed to generate HMAC');
    }
  }

  /**
   * Encrypt data using AES-256-GCM
   */
  encrypt(plaintext, key) {
    try {
      // Generate random IV
      const iv = crypto.randomBytes(this.ivLength);
      
      // Create cipher
      const cipher = crypto.createCipher(this.algorithm, key, iv);
      
      // Encrypt
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Get authentication tag
      const tag = cipher.getAuthTag();
      
      // Combine IV, tag, and encrypted data
      const result = {
        iv: iv.toString('hex'),
        tag: tag.toString('hex'),
        encrypted: encrypted
      };
      
      return Buffer.from(JSON.stringify(result)).toString('base64');
    } catch (error) {
      logger.error('Error encrypting data:', error);
      throw new Error('Failed to encrypt data');
    }
  }

  /**
   * Decrypt data using AES-256-GCM
   */
  decrypt(encryptedData, key) {
    try {
      // Parse encrypted data
      const data = JSON.parse(Buffer.from(encryptedData, 'base64').toString('utf8'));
      const iv = Buffer.from(data.iv, 'hex');
      const tag = Buffer.from(data.tag, 'hex');
      const encrypted = data.encrypted;
      
      // Create decipher
      const decipher = crypto.createDecipher(this.algorithm, key, iv);
      decipher.setAuthTag(tag);
      
      // Decrypt
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      logger.error('Error decrypting data:', error);
      throw new Error('Failed to decrypt data');
    }
  }

  /**
   * Generate encryption key from password
   */
  deriveKey(password, salt, iterations = 100000, keyLength = 32) {
    try {
      return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
    } catch (error) {
      logger.error('Error deriving key:', error);
      throw new Error('Failed to derive key');
    }
  }

  /**
   * Generate salt for key derivation
   */
  generateSalt(length = 32) {
    return crypto.randomBytes(length);
  }

  /**
   * Constant-time string comparison
   */
  constantTimeCompare(a, b) {
    try {
      if (a.length !== b.length) {
        return false;
      }
      
      const bufferA = Buffer.from(a);
      const bufferB = Buffer.from(b);
      
      return crypto.timingSafeEqual(bufferA, bufferB);
    } catch (error) {
      logger.error('Error in constant time compare:', error);
      return false;
    }
  }

  /**
   * Generate TOTP secret
   */
  generateTOTPSecret(length = 32) {
    try {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let secret = '';
      
      for (let i = 0; i < length; i++) {
        secret += chars.charAt(crypto.randomInt(0, chars.length));
      }
      
      return secret;
    } catch (error) {
      logger.error('Error generating TOTP secret:', error);
      throw new Error('Failed to generate TOTP secret');
    }
  }

  /**
   * Generate backup codes for 2FA
   */
  generateBackupCodes(count = 10, length = 8) {
    try {
      const codes = [];
      
      for (let i = 0; i < count; i++) {
        const code = this.generateSecureRandom(length / 2, 'hex').toUpperCase();
        // Format as XXXX-XXXX
        const formattedCode = code.match(/.{1,4}/g).join('-');
        codes.push(formattedCode);
      }
      
      return codes;
    } catch (error) {
      logger.error('Error generating backup codes:', error);
      throw new Error('Failed to generate backup codes');
    }
  }

  /**
   * Generate API key with checksum
   */
  generateAPIKey(prefix = 'authx', length = 32) {
    try {
      const timestamp = Date.now().toString(36);
      const randomPart = this.generateSecureRandom(length / 2, 'hex');
      const keyData = `${prefix}_${timestamp}_${randomPart}`;
      
      // Generate checksum
      const checksum = this.generateHash(keyData, 'sha256').substring(0, 8);
      
      return `${keyData}_${checksum}`;
    } catch (error) {
      logger.error('Error generating API key:', error);
      throw new Error('Failed to generate API key');
    }
  }

  /**
   * Validate API key checksum
   */
  validateAPIKey(apiKey) {
    try {
      const parts = apiKey.split('_');
      if (parts.length !== 4) {
        return false;
      }
      
      const keyData = parts.slice(0, 3).join('_');
      const providedChecksum = parts[3];
      const expectedChecksum = this.generateHash(keyData, 'sha256').substring(0, 8);
      
      return this.constantTimeCompare(providedChecksum, expectedChecksum);
    } catch (error) {
      logger.error('Error validating API key:', error);
      return false;
    }
  }

  /**
   * Generate secure session ID
   */
  generateSessionId() {
    try {
      const timestamp = Date.now().toString(36);
      const randomPart = this.generateSecureRandom(24, 'hex');
      return `${timestamp}_${randomPart}`;
    } catch (error) {
      logger.error('Error generating session ID:', error);
      throw new Error('Failed to generate session ID');
    }
  }

  /**
   * Generate CSRF token
   */
  generateCSRFToken() {
    return this.generateSecureRandom(32, 'base64url');
  }

  /**
   * Generate nonce for CSP
   */
  generateNonce() {
    return this.generateSecureRandom(16, 'base64');
  }

  /**
   * Mask sensitive data for logging
   */
  maskSensitiveData(data, fields = ['password', 'token', 'secret', 'key']) {
    try {
      if (typeof data !== 'object' || data === null) {
        return data;
      }
      
      const masked = { ...data };
      
      for (const field of fields) {
        if (masked[field]) {
          const value = masked[field].toString();
          if (value.length > 8) {
            masked[field] = value.substring(0, 4) + '****' + value.substring(value.length - 4);
          } else {
            masked[field] = '****';
          }
        }
      }
      
      return masked;
    } catch (error) {
      logger.error('Error masking sensitive data:', error);
      return data;
    }
  }

  /**
   * Generate fingerprint for device identification
   */
  generateDeviceFingerprint(userAgent, ip, additionalData = {}) {
    try {
      const fingerprintData = {
        userAgent: userAgent || '',
        ip: ip || '',
        ...additionalData,
        timestamp: Math.floor(Date.now() / (1000 * 60 * 60)) // Hour precision
      };
      
      const dataString = JSON.stringify(fingerprintData);
      return this.generateHash(dataString, 'sha256');
    } catch (error) {
      logger.error('Error generating device fingerprint:', error);
      throw new Error('Failed to generate device fingerprint');
    }
  }

  /**
   * Generate rate limiting key
   */
  generateRateLimitKey(identifier, action, window) {
    try {
      const windowStart = Math.floor(Date.now() / (window * 1000)) * window;
      return `ratelimit:${action}:${identifier}:${windowStart}`;
    } catch (error) {
      logger.error('Error generating rate limit key:', error);
      throw new Error('Failed to generate rate limit key');
    }
  }

  /**
   * Secure random integer
   */
  randomInt(min, max) {
    try {
      return crypto.randomInt(min, max);
    } catch (error) {
      logger.error('Error generating random integer:', error);
      throw new Error('Failed to generate random integer');
    }
  }

  /**
   * Generate OTP code
   */
  generateOTP(length = 6) {
    try {
      let otp = '';
      for (let i = 0; i < length; i++) {
        otp += this.randomInt(0, 10).toString();
      }
      return otp;
    } catch (error) {
      logger.error('Error generating OTP:', error);
      throw new Error('Failed to generate OTP');
    }
  }

  /**
   * Hash OTP for storage
   */
  hashOTP(otp, salt) {
    try {
      return this.generateHMAC(otp, salt, 'sha256');
    } catch (error) {
      logger.error('Error hashing OTP:', error);
      throw new Error('Failed to hash OTP');
    }
  }

  /**
   * Verify OTP
   */
  verifyOTP(otp, hash, salt) {
    try {
      const expectedHash = this.hashOTP(otp, salt);
      return this.constantTimeCompare(hash, expectedHash);
    } catch (error) {
      logger.error('Error verifying OTP:', error);
      return false;
    }
  }
}

module.exports = new CryptoUtils();

