const passport = require('passport');
const logger = require('../utils/logger');
const strategyRegistry = require('./strategyRegistry');
const userService = require('../services/userService');

/**
 * Passport.js configuration and initialization
 * This module sets up Passport with all registered authentication strategies
 */

/**
 * Configure Passport serialization
 */
passport.serializeUser(async (user, done) => {
  try {
    // Use the strategy's serialization method if available
    const strategy = strategyRegistry.get(user.strategy);
    if (strategy && typeof strategy.serializeUser === 'function') {
      const serialized = await strategy.serializeUser(user);
      return done(null, { id: serialized, strategy: user.strategy });
    }

    // Default serialization
    const userId = user.id || user._id;
    done(null, { id: userId, strategy: user.strategy || 'default' });
  } catch (error) {
    logger.error('Error serializing user:', error);
    done(error);
  }
});

/**
 * Configure Passport deserialization
 */
passport.deserializeUser(async (sessionData, done) => {
  try {
    const { id, strategy: strategyName } = sessionData;

    // Use the strategy's deserialization method if available
    const strategy = strategyRegistry.get(strategyName);
    if (strategy && typeof strategy.deserializeUser === 'function') {
      const user = await strategy.deserializeUser(id);
      return done(null, user);
    }

    // Default deserialization using user service
    const user = await userService.findById(id);
    if (!user) {
      return done(null, false);
    }

    done(null, user);
  } catch (error) {
    logger.error('Error deserializing user:', error);
    done(error);
  }
});

/**
 * Initialize Passport with all registered strategies
 */
async function initializePassport() {
  try {
    logger.info('Initializing Passport.js...');

    // Auto-discover and register strategies
    const strategiesRegistered = await strategyRegistry.autoDiscover();
    
    if (strategiesRegistered === 0) {
      logger.warn('No authentication strategies were auto-discovered. Manually registering core strategies...');
      await registerCoreStrategies();
    }

    // Initialize all registered strategies
    await strategyRegistry.initialize();

    // Validate strategy configuration
    const validation = strategyRegistry.validate();
    if (validation.invalid.length > 0) {
      logger.warn('Some strategies have invalid configuration:', validation.invalid);
    }

    if (validation.warnings.length > 0) {
      validation.warnings.forEach(warning => logger.warn(warning));
    }

    // Log strategy statistics
    const stats = strategyRegistry.getStats();
    logger.info('Passport.js initialized successfully', {
      totalStrategies: stats.total,
      enabledStrategies: stats.enabled,
      defaultStrategy: stats.default,
      strategyTypes: stats.types
    });

    return true;
  } catch (error) {
    logger.error('Failed to initialize Passport.js:', error);
    throw error;
  }
}

/**
 * Manually register core strategies if auto-discovery fails
 */
async function registerCoreStrategies() {
  try {
    const config = require('../config/config');

    // Register JWT Strategy
    if (config.jwt.secret) {
      const JWTStrategy = require('./strategies/jwtStrategy');
      const jwtStrategy = new JWTStrategy();
      await strategyRegistry.register(jwtStrategy);
    }

    // Register Local Strategy
    const LocalStrategy = require('./strategies/localStrategy');
    const localStrategy = new LocalStrategy();
    await strategyRegistry.register(localStrategy);

    // Register Google OAuth Strategy
    if (config.oauth.google.clientID && config.oauth.google.clientSecret) {
      const GoogleStrategy = require('./strategies/googleStrategy');
      const googleStrategy = new GoogleStrategy();
      await strategyRegistry.register(googleStrategy);
    }

    // Register GitHub OAuth Strategy
    if (config.oauth.github.clientID && config.oauth.github.clientSecret) {
      const GitHubStrategy = require('./strategies/githubStrategy');
      const githubStrategy = new GitHubStrategy();
      await strategyRegistry.register(githubStrategy);
    }

    // Register SAML Strategy
    if (config.saml.entryPoint && config.saml.cert) {
      const SAMLStrategy = require('./strategies/samlStrategy');
      const samlStrategy = new SAMLStrategy();
      await strategyRegistry.register(samlStrategy);
    }

    // Register LDAP Strategy
    if (config.ldap.url && config.ldap.bindDN) {
      const LDAPStrategy = require('./strategies/ldapStrategy');
      const ldapStrategy = new LDAPStrategy();
      await strategyRegistry.register(ldapStrategy);
    }

    logger.info('Core authentication strategies registered manually');
  } catch (error) {
    logger.error('Failed to register core strategies:', error);
    throw error;
  }
}

/**
 * Get authentication middleware for a specific strategy
 * @param {string} strategyName - Name of the strategy
 * @param {Object} options - Passport authenticate options
 * @returns {Function} Passport middleware
 */
function authenticate(strategyName, options = {}) {
  const strategy = strategyRegistry.get(strategyName);
  if (!strategy) {
    throw new Error(`Authentication strategy '${strategyName}' not found`);
  }

  if (!strategy.enabled) {
    throw new Error(`Authentication strategy '${strategyName}' is disabled`);
  }

  // Default options
  const defaultOptions = {
    session: !strategy.getType() === 'jwt', // JWT strategies are stateless
    failureRedirect: false,
    failureFlash: false
  };

  const mergedOptions = { ...defaultOptions, ...options };

  return passport.authenticate(strategyName, mergedOptions);
}

/**
 * Get authentication middleware for multiple strategies
 * @param {Array<string>} strategyNames - Array of strategy names
 * @param {Object} options - Passport authenticate options
 * @returns {Function} Passport middleware
 */
function authenticateMultiple(strategyNames, options = {}) {
  // Validate all strategies exist and are enabled
  strategyNames.forEach(name => {
    const strategy = strategyRegistry.get(name);
    if (!strategy) {
      throw new Error(`Authentication strategy '${name}' not found`);
    }
    if (!strategy.enabled) {
      throw new Error(`Authentication strategy '${name}' is disabled`);
    }
  });

  return passport.authenticate(strategyNames, options);
}

/**
 * Get available authentication methods for client
 * @returns {Array} Array of available authentication methods
 */
function getAvailableMethods() {
  return strategyRegistry.getMetadata();
}

/**
 * Check if a user is authenticated
 * @param {Object} req - Express request object
 * @returns {boolean} True if user is authenticated
 */
function isAuthenticated(req) {
  return req.isAuthenticated && req.isAuthenticated();
}

/**
 * Get current user from request
 * @param {Object} req - Express request object
 * @returns {Object|null} User object or null
 */
function getCurrentUser(req) {
  return req.user || null;
}

/**
 * Logout user
 * @param {Object} req - Express request object
 * @param {Function} callback - Callback function
 */
function logout(req, callback) {
  req.logout(callback);
}

/**
 * Custom authentication handler with enhanced error handling
 * @param {string} strategyName - Strategy name
 * @param {Object} options - Authentication options
 * @returns {Function} Express middleware
 */
function customAuthenticate(strategyName, options = {}) {
  return (req, res, next) => {
    const strategy = strategyRegistry.get(strategyName);
    if (!strategy) {
      return res.status(400).json({
        success: false,
        error: `Authentication strategy '${strategyName}' not found`
      });
    }

    if (!strategy.enabled) {
      return res.status(400).json({
        success: false,
        error: `Authentication strategy '${strategyName}' is disabled`
      });
    }

    // Execute pre-authentication hook
    strategy.preAuth(req).then(canProceed => {
      if (!canProceed) {
        return res.status(403).json({
          success: false,
          error: 'Authentication not allowed'
        });
      }

      // Use Passport authentication
      passport.authenticate(strategyName, options, async (err, user, info) => {
        try {
          if (err) {
            logger.error(`Authentication error for strategy '${strategyName}':`, err);
            const result = await strategy.handleFailure(err, req);
            return res.status(result.getStatusCode()).json(result.toResponse());
          }

          if (!user) {
            const error = info ? info.message : 'Authentication failed';
            const result = await strategy.handleFailure(new Error(error), req);
            return res.status(result.getStatusCode()).json(result.toResponse());
          }

          // Execute post-authentication hook
          await strategy.postAuth(user, req);

          // Handle successful authentication
          const result = await strategy.handleSuccess(user, null, req);
          
          // Log in user if using sessions
          if (options.session !== false) {
            req.logIn(user, (loginErr) => {
              if (loginErr) {
                logger.error('Login error:', loginErr);
                return next(loginErr);
              }
              return res.status(result.getStatusCode()).json(result.toResponse());
            });
          } else {
            return res.status(result.getStatusCode()).json(result.toResponse());
          }
        } catch (error) {
          logger.error('Post-authentication error:', error);
          return res.status(500).json({
            success: false,
            error: 'Internal authentication error'
          });
        }
      })(req, res, next);
    }).catch(error => {
      logger.error('Pre-authentication error:', error);
      return res.status(500).json({
        success: false,
        error: 'Internal authentication error'
      });
    });
  };
}

module.exports = {
  passport,
  initializePassport,
  authenticate,
  authenticateMultiple,
  customAuthenticate,
  getAvailableMethods,
  isAuthenticated,
  getCurrentUser,
  logout,
  strategyRegistry
};

