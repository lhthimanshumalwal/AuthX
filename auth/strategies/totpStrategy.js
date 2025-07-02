const express = require('express');
const { body, validationResult } = require('express-validator');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const userService = require('../../services/userService');
const cryptoUtils = require('../../utils/cryptoUtils');
const auditService = require('../../services/auditService');
const logger = require('../../utils/logger');
const rateLimiter = require('../../middleware/rateLimiter');
const { isAuthenticated } = require('../../middleware/authMiddleware');

const router = express.Router();

/**
 * TOTP (Time-based One-Time Password) Two-Factor Authentication
 * Implements Google Authenticator compatible 2FA
 */

/**
 * @route POST /auth/2fa/setup
 * @desc Setup TOTP 2FA for user
 * @access Private
 */
router.post('/setup',
  isAuthenticated,
  async (req, res) => {
    try {
      // Check if 2FA is already enabled
      if (req.user.twoFactorAuth?.enabled) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Two-factor authentication is already enabled'
        });
      }

      // Generate secret
      const secret = speakeasy.generateSecret({
        name: `AuthX (${req.user.email})`,
        issuer: 'AuthX',
        length: 32
      });

      // Generate QR code
      const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

      // Generate backup codes
      const backupCodes = cryptoUtils.generateBackupCodes(10);

      // Store secret temporarily (not enabled yet)
      req.user.twoFactorAuth = {
        enabled: false,
        secret: secret.base32,
        backupCodes: backupCodes.map(code => cryptoUtils.hashToken(code)),
        lastUsed: null
      };
      await req.user.save();

      // Log 2FA setup initiation
      await auditService.log('2fa_setup_initiated', {
        userId: req.user._id,
        email: req.user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        message: '2FA setup initiated',
        secret: secret.base32,
        qrCode: qrCodeUrl,
        backupCodes: backupCodes,
        manualEntryKey: secret.base32
      });
    } catch (error) {
      logger.error('2FA setup error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to setup 2FA'
      });
    }
  }
);

/**
 * @route POST /auth/2fa/verify-setup
 * @desc Verify and enable TOTP 2FA
 * @access Private
 */
router.post('/verify-setup',
  isAuthenticated,
  rateLimiter.twoFactor,
  [
    body('token').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Token must be 6 digits')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Token must be 6 digits'
        });
      }

      const { token } = req.body;

      // Check if 2FA setup was initiated
      if (!req.user.twoFactorAuth?.secret || req.user.twoFactorAuth.enabled) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'No 2FA setup in progress or already enabled'
        });
      }

      // Verify token
      const verified = speakeasy.totp.verify({
        secret: req.user.twoFactorAuth.secret,
        encoding: 'base32',
        token: token,
        window: 2 // Allow 2 time steps (60 seconds) tolerance
      });

      if (!verified) {
        await auditService.log('2fa_setup_failed', {
          userId: req.user._id,
          email: req.user.email,
          reason: 'invalid_token',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid verification code'
        });
      }

      // Enable 2FA
      req.user.twoFactorAuth.enabled = true;
      req.user.twoFactorAuth.lastUsed = new Date();
      await req.user.save();

      // Send confirmation email
      const emailService = require('../../services/emailService');
      await emailService.send2FASetupEmail(req.user);

      // Log successful 2FA setup
      await auditService.log('2fa_enabled', {
        userId: req.user._id,
        email: req.user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      logger.info('2FA enabled for user', {
        userId: req.user._id,
        email: req.user.email,
        ip: req.ip
      });

      res.json({
        message: 'Two-factor authentication enabled successfully',
        enabled: true
      });
    } catch (error) {
      logger.error('2FA verify setup error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to verify 2FA setup'
      });
    }
  }
);

/**
 * @route POST /auth/2fa/verify
 * @desc Verify TOTP token for authentication
 * @access Public (but requires partial authentication)
 */
router.post('/verify',
  rateLimiter.twoFactor,
  [
    body('token').isLength({ min: 6, max: 6 }).isNumeric().withMessage('Token must be 6 digits'),
    body('userId').isMongoId().withMessage('Valid user ID is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: errors.array()
        });
      }

      const { token, userId } = req.body;

      // Get user
      const user = await userService.getUserById(userId);
      
      if (!user || !user.twoFactorAuth?.enabled) {
        await auditService.log('2fa_verification_failed', {
          userId: userId,
          reason: 'user_not_found_or_2fa_disabled',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid verification request'
        });
      }

      // Check if account is active
      if (user.status !== 'active') {
        await auditService.log('2fa_verification_failed', {
          userId: user._id,
          reason: 'account_inactive',
          status: user.status,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.status(400).json({
          error: 'Bad Request',
          message: 'Account is not active'
        });
      }

      // Verify TOTP token
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorAuth.secret,
        encoding: 'base32',
        token: token,
        window: 2
      });

      if (!verified) {
        // Check if it's a backup code
        const isBackupCode = await verifyBackupCode(user, token);
        
        if (!isBackupCode) {
          await auditService.log('2fa_verification_failed', {
            userId: user._id,
            email: user.email,
            reason: 'invalid_token',
            ip: req.ip,
            userAgent: req.get('User-Agent')
          });

          return res.status(400).json({
            error: 'Bad Request',
            message: 'Invalid verification code'
          });
        }
      }

      // Update last used
      user.twoFactorAuth.lastUsed = new Date();
      await user.save();

      // Set session as 2FA verified
      if (req.session) {
        req.session.twoFactorVerified = true;
        req.session.userId = user._id;
        req.session.email = user.email;
      }

      // Generate tokens
      const tokenUtils = require('../../utils/tokenUtils');
      const tokens = tokenUtils.generateTokenPair(user);

      // Log successful 2FA verification
      await auditService.log('2fa_verification_success', {
        userId: user._id,
        email: user.email,
        method: verified ? 'totp' : 'backup_code',
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      logger.info('2FA verification successful', {
        userId: user._id,
        email: user.email,
        method: verified ? 'totp' : 'backup_code',
        ip: req.ip
      });

      res.json({
        message: '2FA verification successful',
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          profile: user.profile,
          roles: user.roles.map(r => r.name || r),
          status: user.status,
          emailVerified: user.emailVerified,
          twoFactorEnabled: true
        },
        tokens
      });
    } catch (error) {
      logger.error('2FA verification error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: '2FA verification failed'
      });
    }
  }
);

/**
 * @route POST /auth/2fa/disable
 * @desc Disable TOTP 2FA
 * @access Private
 */
router.post('/disable',
  isAuthenticated,
  [
    body('password').notEmpty().withMessage('Password is required to disable 2FA')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Password is required to disable 2FA'
        });
      }

      const { password } = req.body;

      // Verify password
      const isValidPassword = await req.user.comparePassword(password);
      if (!isValidPassword) {
        await auditService.log('2fa_disable_failed', {
          userId: req.user._id,
          reason: 'invalid_password',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid password'
        });
      }

      // Disable 2FA
      req.user.twoFactorAuth = {
        enabled: false,
        secret: null,
        backupCodes: [],
        lastUsed: null
      };
      await req.user.save();

      // Log 2FA disabled
      await auditService.log('2fa_disabled', {
        userId: req.user._id,
        email: req.user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      logger.info('2FA disabled for user', {
        userId: req.user._id,
        email: req.user.email,
        ip: req.ip
      });

      res.json({
        message: 'Two-factor authentication disabled successfully',
        enabled: false
      });
    } catch (error) {
      logger.error('2FA disable error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to disable 2FA'
      });
    }
  }
);

/**
 * @route POST /auth/2fa/regenerate-backup-codes
 * @desc Regenerate backup codes
 * @access Private
 */
router.post('/regenerate-backup-codes',
  isAuthenticated,
  [
    body('password').notEmpty().withMessage('Password is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Password is required'
        });
      }

      const { password } = req.body;

      // Check if 2FA is enabled
      if (!req.user.twoFactorAuth?.enabled) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Two-factor authentication is not enabled'
        });
      }

      // Verify password
      const isValidPassword = await req.user.comparePassword(password);
      if (!isValidPassword) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid password'
        });
      }

      // Generate new backup codes
      const backupCodes = cryptoUtils.generateBackupCodes(10);
      req.user.twoFactorAuth.backupCodes = backupCodes.map(code => cryptoUtils.hashToken(code));
      await req.user.save();

      // Log backup codes regeneration
      await auditService.log('2fa_backup_codes_regenerated', {
        userId: req.user._id,
        email: req.user.email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        message: 'Backup codes regenerated successfully',
        backupCodes: backupCodes
      });
    } catch (error) {
      logger.error('2FA regenerate backup codes error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to regenerate backup codes'
      });
    }
  }
);

/**
 * Verify backup code
 */
async function verifyBackupCode(user, code) {
  try {
    const hashedCode = cryptoUtils.hashToken(code);
    const codeIndex = user.twoFactorAuth.backupCodes.findIndex(
      storedCode => cryptoUtils.constantTimeCompare(storedCode, hashedCode)
    );

    if (codeIndex === -1) {
      return false;
    }

    // Remove used backup code
    user.twoFactorAuth.backupCodes.splice(codeIndex, 1);
    await user.save();

    // Log backup code usage
    await auditService.log('2fa_backup_code_used', {
      userId: user._id,
      email: user.email,
      remainingCodes: user.twoFactorAuth.backupCodes.length
    });

    return true;
  } catch (error) {
    logger.error('Backup code verification error:', error);
    return false;
  }
}

module.exports = router;

