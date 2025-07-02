const dotenv = require('dotenv');
const path = require('path');

// Load environment variables
dotenv.config();

const config = {
  // Server Configuration
  server: {
    env: process.env.NODE_ENV || 'development',
    port: parseInt(process.env.PORT, 10) || 3000,
    host: process.env.HOST || 'localhost'
  },

  // Database Configuration
  database: {
    mongodb: {
      uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/authx',
      options: {
        useNewUrlParser: true,
        useUnifiedTopology: true
      }
    },
    redis: {
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      options: {
        retryDelayOnFailover: 100,
        enableReadyCheck: false,
        maxRetriesPerRequest: null
      }
    }
  },

  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'fallback-secret-change-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '1h',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    algorithm: 'HS256',
    issuer: 'authx',
    audience: 'authx-users'
  },

  // Session Configuration
  session: {
    secret: process.env.SESSION_SECRET || 'fallback-session-secret',
    maxAge: parseInt(process.env.SESSION_MAX_AGE, 10) || 86400000, // 24 hours
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
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
    issuer: process.env.SAML_ISSUER,
    callbackUrl: process.env.SAML_CALLBACK_URL || 'http://localhost:3000/auth/saml/callback',
    cert: process.env.SAML_CERT,
    privateCert: process.env.SAML_PRIVATE_CERT,
    decryptionPvk: process.env.SAML_DECRYPTION_PVK,
    signatureAlgorithm: 'sha256'
  },

  // LDAP Configuration
  ldap: {
    url: process.env.LDAP_URL,
    bindDN: process.env.LDAP_BIND_DN,
    bindCredentials: process.env.LDAP_BIND_CREDENTIALS,
    searchBase: process.env.LDAP_SEARCH_BASE,
    searchFilter: process.env.LDAP_SEARCH_FILTER || '(uid={{username}})',
    searchAttributes: ['uid', 'mail', 'cn', 'sn', 'givenName'],
    tlsOptions: {
      rejectUnauthorized: process.env.NODE_ENV === 'production'
    }
  },

  // Email Configuration
  email: {
    smtp: {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT, 10) || 587,
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
  rateLimiting: {
    global: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000, // 15 minutes
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100
    },
    login: {
      windowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS, 10) || 900000, // 15 minutes
      max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS, 10) || 5
    }
  },

  // Security Configuration
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
    magicLinkExpiresIn: parseInt(process.env.MAGIC_LINK_EXPIRES_IN, 10) || 600000, // 10 minutes
    otpExpiresIn: parseInt(process.env.OTP_EXPIRES_IN, 10) || 300000, // 5 minutes
    passwordMinLength: 8,
    passwordRequireUppercase: true,
    passwordRequireLowercase: true,
    passwordRequireNumbers: true,
    passwordRequireSymbols: true
  },

  // Audit & Logging
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    auditEnabled: process.env.AUDIT_ENABLED === 'true' || true,
    logFile: path.join(__dirname, '../logs/app.log'),
    errorFile: path.join(__dirname, '../logs/error.log'),
    auditFile: path.join(__dirname, '../logs/audit.log')
  },

  // Admin Configuration
  admin: {
    email: process.env.ADMIN_EMAIL || 'admin@authx.com',
    password: process.env.ADMIN_PASSWORD || 'change-this-password'
  },

  // WebAuthn Configuration
  webauthn: {
    rpName: process.env.WEBAUTHN_RP_NAME || 'AuthX',
    rpID: process.env.WEBAUTHN_RP_ID || 'localhost',
    origin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000'
  },

  // Feature Flags
  features: {
    enableRegistration: process.env.ENABLE_REGISTRATION !== 'false',
    enableEmailVerification: process.env.ENABLE_EMAIL_VERIFICATION !== 'false',
    enablePasswordReset: process.env.ENABLE_PASSWORD_RESET !== 'false',
    enableMFA: process.env.ENABLE_MFA !== 'false',
    enableAuditLogging: process.env.ENABLE_AUDIT_LOGGING !== 'false'
  },

  // CORS Configuration
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
    optionsSuccessStatus: 200
  }
};

// Validation function to check required configuration
config.validate = function() {
  const errors = [];

  // Check JWT secrets in production
  if (config.server.env === 'production') {
    if (config.jwt.secret === 'fallback-secret-change-in-production') {
      errors.push('JWT_SECRET must be set in production');
    }
    if (config.jwt.refreshSecret === 'fallback-refresh-secret') {
      errors.push('JWT_REFRESH_SECRET must be set in production');
    }
    if (config.session.secret === 'fallback-session-secret') {
      errors.push('SESSION_SECRET must be set in production');
    }
  }

  // Check OAuth configuration if strategies are enabled
  if (config.oauth.google.clientID && !config.oauth.google.clientSecret) {
    errors.push('GOOGLE_CLIENT_SECRET is required when GOOGLE_CLIENT_ID is set');
  }
  if (config.oauth.github.clientID && !config.oauth.github.clientSecret) {
    errors.push('GITHUB_CLIENT_SECRET is required when GITHUB_CLIENT_ID is set');
  }

  // Check SAML configuration
  if (config.saml.entryPoint && !config.saml.cert) {
    errors.push('SAML_CERT is required when SAML_ENTRY_POINT is set');
  }

  // Check LDAP configuration
  if (config.ldap.url && (!config.ldap.bindDN || !config.ldap.bindCredentials)) {
    errors.push('LDAP_BIND_DN and LDAP_BIND_CREDENTIALS are required when LDAP_URL is set');
  }

  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
  }

  return true;
};

module.exports = config;

