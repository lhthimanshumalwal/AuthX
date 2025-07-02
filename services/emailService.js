const nodemailer = require('nodemailer');
const config = require('../config/config');
const logger = require('../utils/logger');

class EmailService {
  constructor() {
    this.transporter = null;
    this.initialize();
  }

  /**
   * Initialize email transporter
   */
  async initialize() {
    try {
      if (!config.email.smtp.auth.user || !config.email.smtp.auth.pass) {
        logger.warn('Email service not configured - SMTP credentials missing');
        return;
      }

      this.transporter = nodemailer.createTransporter({
        host: config.email.smtp.host,
        port: config.email.smtp.port,
        secure: config.email.smtp.secure,
        auth: {
          user: config.email.smtp.auth.user,
          pass: config.email.smtp.auth.pass
        },
        tls: {
          rejectUnauthorized: false
        }
      });

      // Verify connection
      await this.transporter.verify();
      logger.info('Email service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize email service:', error);
      this.transporter = null;
    }
  }

  /**
   * Send email
   */
  async sendEmail(to, subject, html, text = null) {
    try {
      if (!this.transporter) {
        logger.warn('Email service not available - skipping email send');
        return { success: false, error: 'Email service not configured' };
      }

      const mailOptions = {
        from: `${config.email.from.name} <${config.email.from.email}>`,
        to: Array.isArray(to) ? to.join(', ') : to,
        subject,
        html,
        text: text || this.htmlToText(html)
      };

      const result = await this.transporter.sendMail(mailOptions);
      
      logger.info(`Email sent successfully to ${to}`, {
        messageId: result.messageId,
        subject
      });

      return { success: true, messageId: result.messageId };
    } catch (error) {
      logger.error('Failed to send email:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Send welcome email
   */
  async sendWelcomeEmail(user) {
    const subject = 'Welcome to AuthX!';
    const html = this.generateWelcomeEmailHTML(user);
    
    return await this.sendEmail(user.email, subject, html);
  }

  /**
   * Send email verification email
   */
  async sendVerificationEmail(user) {
    const verificationUrl = `${this.getBaseUrl()}/auth/verify-email?token=${user.emailVerificationToken}`;
    const subject = 'Verify Your Email Address';
    const html = this.generateVerificationEmailHTML(user, verificationUrl);
    
    return await this.sendEmail(user.email, subject, html);
  }

  /**
   * Send password reset email
   */
  async sendPasswordResetEmail(user, resetToken) {
    const resetUrl = `${this.getBaseUrl()}/auth/reset-password?token=${resetToken}`;
    const subject = 'Reset Your Password';
    const html = this.generatePasswordResetEmailHTML(user, resetUrl);
    
    return await this.sendEmail(user.email, subject, html);
  }

  /**
   * Send magic link email
   */
  async sendMagicLinkEmail(email, magicToken) {
    const magicUrl = `${this.getBaseUrl()}/auth/magic-link?token=${magicToken}`;
    const subject = 'Your Magic Link to Sign In';
    const html = this.generateMagicLinkEmailHTML(email, magicUrl);
    
    return await this.sendEmail(email, subject, html);
  }

  /**
   * Send two-factor authentication setup email
   */
  async send2FASetupEmail(user) {
    const subject = 'Two-Factor Authentication Enabled';
    const html = this.generate2FASetupEmailHTML(user);
    
    return await this.sendEmail(user.email, subject, html);
  }

  /**
   * Send security alert email
   */
  async sendSecurityAlertEmail(user, alertType, details = {}) {
    const subject = 'Security Alert - AuthX Account';
    const html = this.generateSecurityAlertEmailHTML(user, alertType, details);
    
    return await this.sendEmail(user.email, subject, html);
  }

  /**
   * Send account locked email
   */
  async sendAccountLockedEmail(user, lockReason = 'Multiple failed login attempts') {
    const subject = 'Account Temporarily Locked';
    const html = this.generateAccountLockedEmailHTML(user, lockReason);
    
    return await this.sendEmail(user.email, subject, html);
  }

  /**
   * Send login notification email
   */
  async sendLoginNotificationEmail(user, deviceInfo = {}) {
    const subject = 'New Login to Your Account';
    const html = this.generateLoginNotificationEmailHTML(user, deviceInfo);
    
    return await this.sendEmail(user.email, subject, html);
  }

  /**
   * Generate welcome email HTML
   */
  generateWelcomeEmailHTML(user) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Welcome to AuthX</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #007bff; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to AuthX!</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.profile?.displayName || user.email}!</h2>
            <p>Welcome to AuthX, your secure authentication platform. We're excited to have you on board!</p>
            <p>Your account has been successfully created with the following details:</p>
            <ul>
              <li><strong>Email:</strong> ${user.email}</li>
              <li><strong>Account Status:</strong> ${user.status}</li>
              <li><strong>Created:</strong> ${new Date(user.createdAt).toLocaleDateString()}</li>
            </ul>
            <p>To get started, please verify your email address by clicking the button below:</p>
            <p style="text-align: center;">
              <a href="${this.getBaseUrl()}/auth/verify-email?token=${user.emailVerificationToken}" class="button">Verify Email Address</a>
            </p>
            <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} AuthX. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate email verification HTML
   */
  generateVerificationEmailHTML(user, verificationUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Verify Your Email</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #28a745; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .button { display: inline-block; padding: 12px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 4px; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Verify Your Email Address</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.profile?.displayName || user.email}!</h2>
            <p>Thank you for signing up with AuthX. To complete your registration, please verify your email address.</p>
            <p style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #f1f1f1; padding: 10px; border-radius: 4px;">
              ${verificationUrl}
            </p>
            <div class="warning">
              <strong>Security Note:</strong> This verification link will expire in 24 hours. If you didn't create an account with AuthX, please ignore this email.
            </div>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} AuthX. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate password reset email HTML
   */
  generatePasswordResetEmailHTML(user, resetUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Reset Your Password</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .button { display: inline-block; padding: 12px 24px; background: #dc3545; color: white; text-decoration: none; border-radius: 4px; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          .warning { background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Reset Your Password</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.profile?.displayName || user.email}!</h2>
            <p>We received a request to reset your password for your AuthX account.</p>
            <p style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #f1f1f1; padding: 10px; border-radius: 4px;">
              ${resetUrl}
            </p>
            <div class="warning">
              <strong>Security Note:</strong> This password reset link will expire in 1 hour. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
            </div>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} AuthX. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate magic link email HTML
   */
  generateMagicLinkEmailHTML(email, magicUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Your Magic Link</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #6f42c1; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .button { display: inline-block; padding: 12px 24px; background: #6f42c1; color: white; text-decoration: none; border-radius: 4px; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          .warning { background: #e2e3e5; border: 1px solid #d6d8db; padding: 10px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Your Magic Link</h1>
          </div>
          <div class="content">
            <h2>Hello!</h2>
            <p>Click the button below to sign in to your AuthX account:</p>
            <p style="text-align: center;">
              <a href="${magicUrl}" class="button">Sign In with Magic Link</a>
            </p>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; background: #f1f1f1; padding: 10px; border-radius: 4px;">
              ${magicUrl}
            </p>
            <div class="warning">
              <strong>Security Note:</strong> This magic link will expire in 15 minutes and can only be used once. If you didn't request this link, please ignore this email.
            </div>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} AuthX. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate 2FA setup email HTML
   */
  generate2FASetupEmailHTML(user) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Two-Factor Authentication Enabled</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #28a745; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          .success { background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Two-Factor Authentication Enabled</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.profile?.displayName || user.email}!</h2>
            <div class="success">
              <strong>Success!</strong> Two-factor authentication has been successfully enabled on your AuthX account.
            </div>
            <p>Your account is now more secure. You'll need to provide a verification code from your authenticator app when signing in.</p>
            <p><strong>Important:</strong> Make sure to save your backup codes in a secure location. You can use them to access your account if you lose access to your authenticator app.</p>
            <p>If you didn't enable two-factor authentication, please contact our support team immediately.</p>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} AuthX. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate security alert email HTML
   */
  generateSecurityAlertEmailHTML(user, alertType, details) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Security Alert</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          .alert { background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Security Alert</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.profile?.displayName || user.email}!</h2>
            <div class="alert">
              <strong>Security Alert:</strong> ${alertType}
            </div>
            <p>We detected unusual activity on your AuthX account:</p>
            <ul>
              <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
              <li><strong>IP Address:</strong> ${details.ip || 'Unknown'}</li>
              <li><strong>Location:</strong> ${details.location || 'Unknown'}</li>
              <li><strong>Device:</strong> ${details.userAgent || 'Unknown'}</li>
            </ul>
            <p>If this was you, you can ignore this email. If you don't recognize this activity, please:</p>
            <ol>
              <li>Change your password immediately</li>
              <li>Review your account settings</li>
              <li>Enable two-factor authentication if not already enabled</li>
              <li>Contact our support team</li>
            </ol>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} AuthX. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate account locked email HTML
   */
  generateAccountLockedEmailHTML(user, lockReason) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Account Temporarily Locked</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #ffc107; color: #212529; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Account Temporarily Locked</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.profile?.displayName || user.email}!</h2>
            <div class="warning">
              <strong>Account Locked:</strong> Your AuthX account has been temporarily locked for security reasons.
            </div>
            <p><strong>Reason:</strong> ${lockReason}</p>
            <p>Your account will be automatically unlocked after a short period. If you believe this was an error or if you continue to experience issues, please contact our support team.</p>
            <p><strong>Security Tips:</strong></p>
            <ul>
              <li>Use a strong, unique password</li>
              <li>Enable two-factor authentication</li>
              <li>Don't share your login credentials</li>
              <li>Always log out from shared devices</li>
            </ul>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} AuthX. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate login notification email HTML
   */
  generateLoginNotificationEmailHTML(user, deviceInfo) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>New Login Notification</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #17a2b8; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; background: #f9f9f9; }
          .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
          .info { background: #d1ecf1; border: 1px solid #bee5eb; padding: 10px; border-radius: 4px; margin: 10px 0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>New Login to Your Account</h1>
          </div>
          <div class="content">
            <h2>Hello ${user.profile?.displayName || user.email}!</h2>
            <div class="info">
              <strong>New Login Detected:</strong> Someone just signed in to your AuthX account.
            </div>
            <p><strong>Login Details:</strong></p>
            <ul>
              <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
              <li><strong>IP Address:</strong> ${deviceInfo.ip || 'Unknown'}</li>
              <li><strong>Location:</strong> ${deviceInfo.location || 'Unknown'}</li>
              <li><strong>Device:</strong> ${deviceInfo.userAgent || 'Unknown'}</li>
            </ul>
            <p>If this was you, you can ignore this email. If you don't recognize this login, please secure your account immediately by changing your password and enabling two-factor authentication.</p>
          </div>
          <div class="footer">
            <p>&copy; ${new Date().getFullYear()} AuthX. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Convert HTML to plain text
   */
  htmlToText(html) {
    return html
      .replace(/<[^>]*>/g, '')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .trim();
  }

  /**
   * Get base URL for email links
   */
  getBaseUrl() {
    return process.env.BASE_URL || `http://localhost:${config.server.port}`;
  }

  /**
   * Test email configuration
   */
  async testConnection() {
    try {
      if (!this.transporter) {
        throw new Error('Email service not initialized');
      }

      await this.transporter.verify();
      return { success: true, message: 'Email service is working correctly' };
    } catch (error) {
      logger.error('Email service test failed:', error);
      return { success: false, error: error.message };
    }
  }
}

module.exports = new EmailService();

