const passport = require('passport');
const config = require('../config/config');
const logger = require('../utils/logger');

// Import strategies
const jwtStrategy = require('./strategies/jwtStrategy');
const localStrategy = require('./strategies/localStrategy');
const googleStrategy = require('./strategies/googleStrategy');
const githubStrategy = require('./strategies/githubStrategy');
const samlStrategy = require('./strategies/samlStrategy');
const ldapStrategy = require('./strategies/ldapStrategy');

class PassportConfig {
  constructor() {
    this.strategies = new Map();
    this.initialize();
  }

  /**
   * Initialize Passport configuration
   */
  initialize() {
    try {
      // Configure session serialization
      this.configureSession();
      
      // Register strategies
      this.registerStrategies();
      
      logger.info('Passport configuration initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize Passport configuration:', error);
      throw error;
    }
  }

  /**
   * Configure session serialization
   */
  configureSession() {
    // Serialize user for session
    passport.serializeUser((user, done) => {
      try {
        // Store only user ID in session
        done(null, user._id.toString());
      } catch (error) {
        logger.error('Error serializing user:', error);
        done(error);
      }
    });

    // Deserialize user from session
    passport.deserializeUser(async (userId, done) => {
      try {
        const userService = require('../services/userService');
        const user = await userService.getUserById(userId);
        
        if (!user) {
          return done(null, false);
        }
        
        // Check if user is still active
        if (user.status !== 'active') {
          return done(null, false);
        }
        
        done(null, user);
      } catch (error) {
        logger.error('Error deserializing user:', error);
        done(error);
      }
    });
  }

  /**
   * Register authentication strategies
   */
  registerStrategies() {
    // Always register JWT strategy (for API authentication)
    this.registerStrategy('jwt', jwtStrategy);
    
    // Always register local strategy (for email/password authentication)
    this.registerStrategy('local', localStrategy);
    
    // Register OAuth strategies if configured
    if (config.oauth.google.clientID && config.oauth.google.clientSecret) {
      this.registerStrategy('google', googleStrategy);
    } else {
      logger.warn('Google OAuth not configured - skipping Google strategy');
    }
    
    if (config.oauth.github.clientID && config.oauth.github.clientSecret) {
      this.registerStrategy('github', githubStrategy);
    } else {
      logger.warn('GitHub OAuth not configured - skipping GitHub strategy');
    }
    
    // Register SAML strategy if configured
    if (config.saml.entryPoint) {
      this.registerStrategy('saml', samlStrategy);
    } else {
      logger.warn('SAML not configured - skipping SAML strategy');
    }
    
    // Register LDAP strategy if configured
    if (config.ldap.server.url && config.ldap.server.bindDN) {
      this.registerStrategy('ldap', ldapStrategy);
    } else {
      logger.warn('LDAP not configured - skipping LDAP strategy');
    }
  }

  /**
   * Register a strategy
   */
  registerStrategy(name, strategy) {
    try {
      if (typeof strategy === 'function') {
        // Strategy is a factory function
        const strategyInstance = strategy();
        passport.use(name, strategyInstance);
        this.strategies.set(name, strategyInstance);
      } else {
        // Strategy is already instantiated
        passport.use(name, strategy);
        this.strategies.set(name, strategy);
      }
      
      logger.info(`Registered authentication strategy: ${name}`);
    } catch (error) {
      logger.error(`Failed to register strategy ${name}:`, error);
    }
  }

  /**
   * Get registered strategy
   */
  getStrategy(name) {
    return this.strategies.get(name);
  }

  /**
   * Get all registered strategies
   */
  getStrategies() {
    return Array.from(this.strategies.keys());
  }

  /**
   * Check if strategy is registered
   */
  hasStrategy(name) {
    return this.strategies.has(name);
  }

  /**
   * Unregister a strategy
   */
  unregisterStrategy(name) {
    try {
      passport.unuse(name);
      this.strategies.delete(name);
      logger.info(`Unregistered authentication strategy: ${name}`);
    } catch (error) {
      logger.error(`Failed to unregister strategy ${name}:`, error);
    }
  }

  /**
   * Dynamically add a new strategy
   */
  addStrategy(name, strategy, options = {}) {
    try {
      if (this.hasStrategy(name)) {
        if (!options.overwrite) {
          throw new Error(`Strategy ${name} already exists`);
        }
        this.unregisterStrategy(name);
      }
      
      this.registerStrategy(name, strategy);
      return true;
    } catch (error) {
      logger.error(`Failed to add strategy ${name}:`, error);
      return false;
    }
  }

  /**
   * Get strategy configuration
   */
  getStrategyConfig(name) {
    const configs = {
      jwt: {
        name: 'JWT',
        description: 'JSON Web Token authentication for APIs',
        type: 'token',
        enabled: true
      },
      local: {
        name: 'Local',
        description: 'Email and password authentication',
        type: 'credentials',
        enabled: true
      },
      google: {
        name: 'Google',
        description: 'Google OAuth 2.0 authentication',
        type: 'oauth',
        enabled: this.hasStrategy('google')
      },
      github: {
        name: 'GitHub',
        description: 'GitHub OAuth authentication',
        type: 'oauth',
        enabled: this.hasStrategy('github')
      },
      saml: {
        name: 'SAML',
        description: 'SAML 2.0 Single Sign-On',
        type: 'sso',
        enabled: this.hasStrategy('saml')
      },
      ldap: {
        name: 'LDAP',
        description: 'LDAP/Active Directory authentication',
        type: 'directory',
        enabled: this.hasStrategy('ldap')
      }
    };
    
    return configs[name] || null;
  }

  /**
   * Get all strategy configurations
   */
  getAllStrategyConfigs() {
    const strategies = ['jwt', 'local', 'google', 'github', 'saml', 'ldap'];
    const configs = {};
    
    strategies.forEach(strategy => {
      configs[strategy] = this.getStrategyConfig(strategy);
    });
    
    return configs;
  }

  /**
   * Validate strategy configuration
   */
  validateStrategyConfig(name) {
    const validations = {
      jwt: () => {
        return config.jwt.secret && config.jwt.secret !== 'fallback-secret-change-in-production';
      },
      local: () => {
        return true; // Local strategy doesn't require external configuration
      },
      google: () => {
        return config.oauth.google.clientID && 
               config.oauth.google.clientSecret && 
               config.oauth.google.callbackURL;
      },
      github: () => {
        return config.oauth.github.clientID && 
               config.oauth.github.clientSecret && 
               config.oauth.github.callbackURL;
      },
      saml: () => {
        return config.saml.entryPoint && 
               config.saml.issuer && 
               config.saml.callbackUrl;
      },
      ldap: () => {
        return config.ldap.server.url && 
               config.ldap.server.bindDN && 
               config.ldap.server.bindCredentials;
      }
    };
    
    const validator = validations[name];
    return validator ? validator() : false;
  }

  /**
   * Get authentication middleware for strategy
   */
  authenticate(strategy, options = {}) {
    return passport.authenticate(strategy, {
      session: options.session !== false,
      failureRedirect: options.failureRedirect,
      successRedirect: options.successRedirect,
      failureFlash: options.failureFlash,
      successFlash: options.successFlash,
      ...options
    });
  }

  /**
   * Create custom authentication middleware
   */
  createAuthMiddleware(strategies, options = {}) {
    return (req, res, next) => {
      const strategyList = Array.isArray(strategies) ? strategies : [strategies];
      
      // Try each strategy in order
      const tryNextStrategy = (index) => {
        if (index >= strategyList.length) {
          return res.status(401).json({
            error: 'Unauthorized',
            message: 'Authentication failed for all strategies'
          });
        }
        
        const strategy = strategyList[index];
        
        passport.authenticate(strategy, (err, user, info) => {
          if (err) {
            return next(err);
          }
          
          if (user) {
            req.user = user;
            req.authStrategy = strategy;
            return next();
          }
          
          // Try next strategy
          tryNextStrategy(index + 1);
        })(req, res, next);
      };
      
      tryNextStrategy(0);
    };
  }

  /**
   * Get authentication status
   */
  getAuthStatus() {
    const strategies = this.getAllStrategyConfigs();
    const status = {
      initialized: true,
      totalStrategies: Object.keys(strategies).length,
      enabledStrategies: Object.values(strategies).filter(s => s.enabled).length,
      strategies: strategies,
      validationResults: {}
    };
    
    // Validate each strategy
    Object.keys(strategies).forEach(name => {
      status.validationResults[name] = this.validateStrategyConfig(name);
    });
    
    return status;
  }
}

// Create singleton instance
const passportConfig = new PassportConfig();

// Export the configured passport instance and utilities
module.exports = {
  passport,
  passportConfig,
  authenticate: (strategy, options) => passportConfig.authenticate(strategy, options),
  getStrategies: () => passportConfig.getStrategies(),
  getAuthStatus: () => passportConfig.getAuthStatus(),
  addStrategy: (name, strategy, options) => passportConfig.addStrategy(name, strategy, options)
};

