const passport = require('passport');
const logger = require('../utils/logger');
const AuthStrategy = require('./interfaces/AuthStrategy');

/**
 * Strategy Registry - Manages all authentication strategies
 * Provides a centralized way to register, configure, and manage authentication strategies
 */
class StrategyRegistry {
  constructor() {
    this.strategies = new Map();
    this.initialized = false;
    this.defaultStrategy = null;
  }

  /**
   * Register a new authentication strategy
   * @param {AuthStrategy} strategy - Strategy instance
   * @returns {Promise<boolean>} True if registered successfully
   */
  async register(strategy) {
    try {
      // Validate strategy
      if (!(strategy instanceof AuthStrategy)) {
        throw new Error('Strategy must extend AuthStrategy base class');
      }

      if (!strategy.name) {
        throw new Error('Strategy must have a name');
      }

      if (this.strategies.has(strategy.name)) {
        throw new Error(`Strategy '${strategy.name}' is already registered`);
      }

      // Validate strategy configuration
      if (!strategy.validateConfig()) {
        throw new Error(`Strategy '${strategy.name}' configuration is invalid`);
      }

      // Initialize the strategy
      await strategy.initialize();

      // Register with registry
      this.strategies.set(strategy.name, strategy);

      // Set as default if it's the first enabled strategy or has higher priority
      if (!this.defaultStrategy || 
          (strategy.enabled && strategy.priority > this.defaultStrategy.priority)) {
        this.defaultStrategy = strategy;
      }

      logger.info(`Authentication strategy '${strategy.name}' registered successfully`, {
        type: strategy.getType(),
        enabled: strategy.enabled,
        priority: strategy.priority
      });

      return true;
    } catch (error) {
      logger.error(`Failed to register strategy '${strategy.name}':`, error);
      throw error;
    }
  }

  /**
   * Unregister a strategy
   * @param {string} name - Strategy name
   * @returns {Promise<boolean>} True if unregistered successfully
   */
  async unregister(name) {
    try {
      const strategy = this.strategies.get(name);
      if (!strategy) {
        throw new Error(`Strategy '${name}' not found`);
      }

      // Cleanup strategy
      await strategy.cleanup();

      // Remove from Passport
      passport.unuse(name);

      // Remove from registry
      this.strategies.delete(name);

      // Update default strategy if necessary
      if (this.defaultStrategy && this.defaultStrategy.name === name) {
        this.defaultStrategy = this.findBestDefaultStrategy();
      }

      logger.info(`Authentication strategy '${name}' unregistered successfully`);
      return true;
    } catch (error) {
      logger.error(`Failed to unregister strategy '${name}':`, error);
      throw error;
    }
  }

  /**
   * Get a strategy by name
   * @param {string} name - Strategy name
   * @returns {AuthStrategy|null} Strategy instance or null
   */
  get(name) {
    return this.strategies.get(name) || null;
  }

  /**
   * Get all registered strategies
   * @returns {Array<AuthStrategy>} Array of strategy instances
   */
  getAll() {
    return Array.from(this.strategies.values());
  }

  /**
   * Get enabled strategies only
   * @returns {Array<AuthStrategy>} Array of enabled strategy instances
   */
  getEnabled() {
    return this.getAll().filter(strategy => strategy.enabled);
  }

  /**
   * Get strategies by type
   * @param {string} type - Strategy type (jwt, oauth, saml, etc.)
   * @returns {Array<AuthStrategy>} Array of matching strategies
   */
  getByType(type) {
    return this.getAll().filter(strategy => strategy.getType() === type);
  }

  /**
   * Check if a strategy is registered
   * @param {string} name - Strategy name
   * @returns {boolean} True if registered
   */
  has(name) {
    return this.strategies.has(name);
  }

  /**
   * Get default strategy
   * @returns {AuthStrategy|null} Default strategy or null
   */
  getDefault() {
    return this.defaultStrategy;
  }

  /**
   * Set default strategy
   * @param {string} name - Strategy name
   * @returns {boolean} True if set successfully
   */
  setDefault(name) {
    const strategy = this.strategies.get(name);
    if (!strategy) {
      throw new Error(`Strategy '${name}' not found`);
    }

    if (!strategy.enabled) {
      throw new Error(`Strategy '${name}' is not enabled`);
    }

    this.defaultStrategy = strategy;
    logger.info(`Default authentication strategy set to '${name}'`);
    return true;
  }

  /**
   * Initialize all registered strategies
   * @returns {Promise<void>}
   */
  async initialize() {
    try {
      logger.info('Initializing authentication strategies...');

      const enabledStrategies = this.getEnabled();
      if (enabledStrategies.length === 0) {
        logger.warn('No authentication strategies are enabled');
        return;
      }

      // Sort strategies by priority (highest first)
      enabledStrategies.sort((a, b) => b.priority - a.priority);

      // Initialize each strategy
      for (const strategy of enabledStrategies) {
        try {
          await strategy.initialize();
          logger.info(`Strategy '${strategy.name}' initialized successfully`);
        } catch (error) {
          logger.error(`Failed to initialize strategy '${strategy.name}':`, error);
          // Disable failed strategy
          strategy.enabled = false;
        }
      }

      this.initialized = true;
      logger.info(`Authentication system initialized with ${this.getEnabled().length} strategies`);
    } catch (error) {
      logger.error('Failed to initialize authentication strategies:', error);
      throw error;
    }
  }

  /**
   * Get registry statistics
   * @returns {Object} Registry statistics
   */
  getStats() {
    const strategies = this.getAll();
    const enabled = this.getEnabled();
    
    const typeStats = {};
    strategies.forEach(strategy => {
      const type = strategy.getType();
      typeStats[type] = (typeStats[type] || 0) + 1;
    });

    return {
      total: strategies.length,
      enabled: enabled.length,
      disabled: strategies.length - enabled.length,
      default: this.defaultStrategy ? this.defaultStrategy.name : null,
      types: typeStats,
      strategies: strategies.map(strategy => strategy.getMetadata())
    };
  }

  /**
   * Get strategy metadata for API responses
   * @returns {Array} Array of strategy metadata
   */
  getMetadata() {
    return this.getEnabled().map(strategy => ({
      name: strategy.name,
      type: strategy.getType(),
      requiresRedirect: strategy.requiresRedirect(),
      supportsRefresh: strategy.supportsRefresh(),
      supportsMFA: strategy.supportsMFA(),
      routes: strategy.getRoutes()
    }));
  }

  /**
   * Validate all strategies
   * @returns {Object} Validation results
   */
  validate() {
    const results = {
      valid: [],
      invalid: [],
      warnings: []
    };

    this.getAll().forEach(strategy => {
      try {
        if (strategy.validateConfig()) {
          results.valid.push(strategy.name);
        } else {
          results.invalid.push({
            name: strategy.name,
            error: 'Configuration validation failed'
          });
        }
      } catch (error) {
        results.invalid.push({
          name: strategy.name,
          error: error.message
        });
      }
    });

    // Check for warnings
    if (results.valid.length === 0) {
      results.warnings.push('No valid authentication strategies found');
    }

    if (!this.defaultStrategy) {
      results.warnings.push('No default authentication strategy set');
    }

    return results;
  }

  /**
   * Find the best default strategy based on priority and type
   * @returns {AuthStrategy|null} Best default strategy
   */
  findBestDefaultStrategy() {
    const enabled = this.getEnabled();
    if (enabled.length === 0) {
      return null;
    }

    // Sort by priority (highest first)
    enabled.sort((a, b) => b.priority - a.priority);

    // Prefer JWT strategies for APIs, then local, then OAuth
    const preferredTypes = ['jwt', 'local', 'oauth', 'saml', 'ldap'];
    
    for (const type of preferredTypes) {
      const strategy = enabled.find(s => s.getType() === type);
      if (strategy) {
        return strategy;
      }
    }

    // Return the highest priority strategy
    return enabled[0];
  }

  /**
   * Cleanup all strategies
   * @returns {Promise<void>}
   */
  async cleanup() {
    try {
      logger.info('Cleaning up authentication strategies...');

      const cleanupPromises = this.getAll().map(async (strategy) => {
        try {
          await strategy.cleanup();
          logger.debug(`Strategy '${strategy.name}' cleaned up successfully`);
        } catch (error) {
          logger.error(`Failed to cleanup strategy '${strategy.name}':`, error);
        }
      });

      await Promise.all(cleanupPromises);

      this.strategies.clear();
      this.defaultStrategy = null;
      this.initialized = false;

      logger.info('All authentication strategies cleaned up');
    } catch (error) {
      logger.error('Failed to cleanup authentication strategies:', error);
      throw error;
    }
  }

  /**
   * Auto-discover and register strategies from directory
   * @param {string} strategiesDir - Directory containing strategy files
   * @returns {Promise<number>} Number of strategies registered
   */
  async autoDiscover(strategiesDir = './strategies') {
    const fs = require('fs').promises;
    const path = require('path');

    try {
      const files = await fs.readdir(path.resolve(__dirname, strategiesDir));
      const strategyFiles = files.filter(file => 
        file.endsWith('Strategy.js') && file !== 'AuthStrategy.js'
      );

      let registered = 0;

      for (const file of strategyFiles) {
        try {
          const StrategyClass = require(path.resolve(__dirname, strategiesDir, file));
          const strategy = new StrategyClass();
          
          if (strategy.enabled) {
            await this.register(strategy);
            registered++;
          }
        } catch (error) {
          logger.error(`Failed to auto-register strategy from '${file}':`, error);
        }
      }

      logger.info(`Auto-discovered and registered ${registered} authentication strategies`);
      return registered;
    } catch (error) {
      logger.error('Failed to auto-discover strategies:', error);
      return 0;
    }
  }
}

// Create singleton instance
const strategyRegistry = new StrategyRegistry();

module.exports = strategyRegistry;

