const express = require('express');
const { body, query, validationResult } = require('express-validator');
const userService = require('../../services/userService');
const tokenUtils = require('../../utils/tokenUtils');
const emailService = require('../../services/emailService');
const auditService = require('../../services/auditService');
const logger = require('../../utils/logger');
const rateLimiter = require('../../middleware/rateLimiter');

const router = express.Router();

/**
 * Magic Link Authentication Strategy
 * Allows users to login via email links without passwords
 */

/**
 * @route POST /auth/magic-link/request
 * @desc Request magic link for authentication
 * @access Public
 */
router.post('/request',
  rateLimiter.login,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Valid email is required'
        });
      }

      const { email } = req.body;

      // Check if user exists
      const user = await userService.getUserByEmail(email);
      
      if (!user) {
        // Don't reveal if user exists for security
        return res.json({
          message: 'If the email exists, a magic link has been sent'
        });
      }

      // Check if account is active
      if (user.status !== 'active') {
        await auditService.log('magic_link_failed', {
          email: email,
          reason: 'account_inactive',
          status: user.status,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.json({
          message: 'If the email exists, a magic link has been sent'
        });
      }

      // Check if account is locked
      if (user.isLocked) {
        await auditService.log('magic_link_failed', {
          userId: user._id,
          email: email,
          reason: 'account_locked',
          lockUntil: user.lockUntil,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.json({
          message: 'If the email exists, a magic link has been sent'
        });
      }

      // Generate magic link token
      const magicToken = tokenUtils.generateMagicLinkToken(email);

      // Send magic link email
      await emailService.sendMagicLinkEmail(email, magicToken);

      // Log magic link request
      await auditService.log('magic_link_requested', {
        userId: user._id,
        email: email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      logger.info('Magic link requested', {
        userId: user._id,
        email: email,
        ip: req.ip
      });

      res.json({
        message: 'If the email exists, a magic link has been sent'
      });
    } catch (error) {
      logger.error('Magic link request error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to process magic link request'
      });
    }
  }
);

/**
 * @route GET /auth/magic-link/verify
 * @desc Verify magic link and authenticate user
 * @access Public
 */
router.get('/verify',
  [
    query('token').notEmpty().withMessage('Magic link token is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Magic link token is required'
        });
      }

      const { token } = req.query;

      // Verify magic link token
      const decoded = tokenUtils.verifyMagicLinkToken(token);
      
      if (!decoded || !decoded.email) {
        await auditService.log('magic_link_failed', {
          reason: 'invalid_token',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid or expired magic link'
        });
      }

      // Get user
      const user = await userService.getUserByEmail(decoded.email);
      
      if (!user) {
        await auditService.log('magic_link_failed', {
          email: decoded.email,
          reason: 'user_not_found',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid magic link'
        });
      }

      // Check if account is active
      if (user.status !== 'active') {
        await auditService.log('magic_link_failed', {
          userId: user._id,
          email: user.email,
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

      // Check if account is locked
      if (user.isLocked) {
        await auditService.log('magic_link_failed', {
          userId: user._id,
          email: user.email,
          reason: 'account_locked',
          lockUntil: user.lockUntil,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });

        return res.status(400).json({
          error: 'Bad Request',
          message: 'Account is temporarily locked'
        });
      }

      // Update last login
      user.lastLogin = new Date();
      user.lastLoginIP = req.ip;
      await user.save();

      // Create device info
      const deviceInfo = {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        provider: 'magic-link',
        timestamp: new Date()
      };

      // Add session to user
      if (req.session) {
        await user.addSession(req.session.id, deviceInfo);
        req.session.userId = user._id;
        req.session.email = user.email;
      }

      // Generate tokens
      const tokens = tokenUtils.generateTokenPair(user);

      // Log successful magic link authentication
      await auditService.log('magic_link_success', {
        userId: user._id,
        email: user.email,
        deviceInfo,
        tokenId: decoded.tokenId
      });

      logger.info('Magic link authentication successful', {
        userId: user._id,
        email: user.email,
        ip: req.ip
      });

      res.json({
        message: 'Magic link authentication successful',
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          profile: user.profile,
          roles: user.roles.map(r => r.name || r),
          status: user.status,
          emailVerified: user.emailVerified,
          twoFactorEnabled: user.twoFactorAuth?.enabled || false
        },
        tokens
      });
    } catch (error) {
      logger.error('Magic link verification error:', error);
      
      if (error.message.includes('expired')) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Magic link has expired'
        });
      }

      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Magic link verification failed'
      });
    }
  }
);

module.exports = router;

