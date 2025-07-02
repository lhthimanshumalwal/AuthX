const dotenv = require('dotenv');
const path = require('path');

// Load environment variables
dotenv.config();

const config = {
  // Server Configuration
  server: {
    port: process.env.PORT || 3000,
    env: process.env.NODE_ENV || 'development',
    host: process.env.HOST || 'localhost'
  },

  // Database Configuration
  database: {
    mongodb: {
      uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/authx',
      options: {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      }
    },
    redis: {
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      options: {
        retryDelayOnFailover: 100,
        enableReadyCheck: false,
        maxRetriesPerRequest: null,
      }
    }
  },

  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'fallback-secret-change-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: 'authx',
    audience: 'authx-users'
  },

  // Session Configuration
  session: {
    secret: process.env.SESSION_SECRET || 'fallback-session-secret',
    maxAge: parseInt(process.env.SESSION_MAX_AGE) || 86400000, // 24 hours
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'strict'
  },

  // OAuth2 Providers
  oauth: {
    google: {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
      scope: ['profile', 'email']
    },
    github: {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL || 'http://localhost:3000/auth/github/callback',
      scope: ['user:email']
    }
  },

  // SAML Configuration
  saml: {
    entryPoint: process.env.SAML_ENTRY_POINT,
    issuer: process.env.SAML_ISSUER || 'authx-app',
    callbackUrl: process.env.SAML_CALLBACK_URL || 'http://localhost:3000/auth/saml/callback',
    cert: process.env.SAML_CERT || null,
    certPath: process.env.SAML_CERT_PATH || null,
    signatureAlgorithm: 'sha256',
    digestAlgorithm: 'sha256'
  },

  // LDAP Configuration
  ldap: {
    server: {
      url: process.env.LDAP_URL || 'ldap://localhost:389',
      bindDN: process.env.LDAP_BIND_DN,
      bindCredentials: process.env.LDAP_BIND_CREDENTIALS,
      searchBase: process.env.LDAP_SEARCH_BASE,
      searchFilter: process.env.LDAP_SEARCH_FILTER || '(uid={{username}})',
      searchAttributes: ['uid', 'mail', 'cn', 'sn', 'givenName']
    }
  },

  // Email Configuration
  email: {
    smtp: {
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    },
    from: {
      email: process.env.FROM_EMAIL || 'noreply@authx.com',
      name: process.env.FROM_NAME || 'AuthX'
    }
  },

  // Rate Limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
  },

  // Login Rate Limiting
  loginRateLimit: {
    windowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
    max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS) || 5,
    message: 'Too many login attempts, please try again later.',
    skipSuccessfulRequests: true
  },

  // Security Configuration
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
    passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH) || 8,
    requireEmailVerification: process.env.REQUIRE_EMAIL_VERIFICATION === 'true',
    enable2FA: process.env.ENABLE_2FA === 'true',
    maxLoginAttempts: 5,
    lockoutTime: 30 * 60 * 1000, // 30 minutes
    passwordResetExpiry: 60 * 60 * 1000, // 1 hour
    emailVerificationExpiry: 24 * 60 * 60 * 1000 // 24 hours
  },

  // Logging Configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    enableAuditLogging: process.env.ENABLE_AUDIT_LOGGING === 'true',
    auditLogRetentionDays: parseInt(process.env.AUDIT_LOG_RETENTION_DAYS) || 90
  },

  // Admin Configuration
  admin: {
    email: process.env.ADMIN_EMAIL || 'admin@authx.com',
    password: process.env.ADMIN_PASSWORD || 'change-this-admin-password'
  },

  // Feature Flags
  features: {
    enableRegistration: process.env.ENABLE_REGISTRATION !== 'false',
    enablePasswordReset: process.env.ENABLE_PASSWORD_RESET !== 'false',
    enableEmailVerification: process.env.ENABLE_EMAIL_VERIFICATION === 'true',
    enableMagicLink: process.env.ENABLE_MAGIC_LINK === 'true',
    enableWebAuthn: process.env.ENABLE_WEBAUTHN === 'true',
    enableAuditLog: process.env.ENABLE_AUDIT_LOG === 'true'
  },

  // CORS Configuration
  cors: {
    origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : ['http://localhost:3000', 'http://localhost:3001'],
    credentials: true,
    optionsSuccessStatus: 200
  }
};

// Validation function to check required environment variables
config.validate = () => {
  const required = [];
  
  if (!config.jwt.secret || config.jwt.secret === 'fallback-secret-change-in-production') {
    required.push('JWT_SECRET');
  }
  
  if (!config.session.secret || config.session.secret === 'fallback-session-secret') {
    required.push('SESSION_SECRET');
  }
  
  if (config.server.env === 'production') {
    if (!config.database.mongodb.uri.includes('mongodb://') && !config.database.mongodb.uri.includes('mongodb+srv://')) {
      required.push('MONGODB_URI');
    }
  }
  
  if (required.length > 0) {
    throw new Error(`Missing required environment variables: ${required.join(', ')}`);
  }
  
  return true;
};

module.exports = config;

