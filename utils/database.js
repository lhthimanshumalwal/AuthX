const mongoose = require('mongoose');
const config = require('../config/config');
const logger = require('./logger');

class DatabaseConnection {
  constructor() {
    this.isConnected = false;
    this.connectionAttempts = 0;
    this.maxRetries = 5;
    this.retryDelay = 5000; // 5 seconds
  }

  /**
   * Connect to MongoDB
   */
  async connect() {
    try {
      // Set mongoose options
      mongoose.set('strictQuery', false);
      
      // Connection event handlers
      mongoose.connection.on('connected', () => {
        logger.info('MongoDB connected successfully');
        this.isConnected = true;
        this.connectionAttempts = 0;
      });

      mongoose.connection.on('error', (error) => {
        logger.error('MongoDB connection error:', error);
        this.isConnected = false;
      });

      mongoose.connection.on('disconnected', () => {
        logger.warn('MongoDB disconnected');
        this.isConnected = false;
        
        // Attempt to reconnect
        if (this.connectionAttempts < this.maxRetries) {
          this.connectionAttempts++;
          logger.info(`Attempting to reconnect to MongoDB (${this.connectionAttempts}/${this.maxRetries})...`);
          setTimeout(() => this.connect(), this.retryDelay);
        } else {
          logger.error('Max reconnection attempts reached. Please check your MongoDB connection.');
        }
      });

      mongoose.connection.on('reconnected', () => {
        logger.info('MongoDB reconnected successfully');
        this.isConnected = true;
        this.connectionAttempts = 0;
      });

      // Connect to MongoDB
      await mongoose.connect(config.database.mongodb.uri, config.database.mongodb.options);
      
      // Initialize default data
      await this.initializeDefaultData();
      
      return mongoose.connection;
    } catch (error) {
      logger.error('Failed to connect to MongoDB:', error);
      this.isConnected = false;
      
      if (this.connectionAttempts < this.maxRetries) {
        this.connectionAttempts++;
        logger.info(`Retrying MongoDB connection (${this.connectionAttempts}/${this.maxRetries})...`);
        setTimeout(() => this.connect(), this.retryDelay);
      } else {
        throw error;
      }
    }
  }

  /**
   * Disconnect from MongoDB
   */
  async disconnect() {
    try {
      await mongoose.disconnect();
      logger.info('MongoDB disconnected gracefully');
      this.isConnected = false;
    } catch (error) {
      logger.error('Error disconnecting from MongoDB:', error);
      throw error;
    }
  }

  /**
   * Check connection status
   */
  isHealthy() {
    return this.isConnected && mongoose.connection.readyState === 1;
  }

  /**
   * Get connection statistics
   */
  getStats() {
    const connection = mongoose.connection;
    return {
      readyState: connection.readyState,
      host: connection.host,
      port: connection.port,
      name: connection.name,
      collections: Object.keys(connection.collections),
      isConnected: this.isConnected
    };
  }

  /**
   * Initialize default data (roles, admin user, etc.)
   */
  async initializeDefaultData() {
    try {
      // Import models
      const Role = require('../models/Role');
      const User = require('../models/User');
      
      // Create default roles
      await Role.createDefaultRoles();
      logger.info('Default roles initialized');

      // Create admin user if it doesn't exist
      const adminEmail = config.admin.email;
      const existingAdmin = await User.findOne({ email: adminEmail });
      
      if (!existingAdmin) {
        const adminRole = await Role.findOne({ name: 'super_admin' });
        
        const adminUser = new User({
          email: adminEmail,
          password: config.admin.password,
          profile: {
            displayName: 'System Administrator',
            firstName: 'System',
            lastName: 'Administrator'
          },
          roles: [adminRole._id],
          status: 'active',
          emailVerified: true,
          authProviders: ['local']
        });

        await adminUser.save();
        logger.info(`Admin user created: ${adminEmail}`);
      }
    } catch (error) {
      logger.error('Error initializing default data:', error);
      // Don't throw error here as it's not critical for startup
    }
  }

  /**
   * Clean up expired data
   */
  async cleanup() {
    try {
      const Session = require('../models/Session');
      
      // Clean up expired sessions
      const deletedSessions = await Session.cleanupExpired();
      if (deletedSessions > 0) {
        logger.info(`Cleaned up ${deletedSessions} expired sessions`);
      }

      // Clean up expired tokens (if stored in database)
      // Add more cleanup tasks as needed
      
    } catch (error) {
      logger.error('Error during database cleanup:', error);
    }
  }

  /**
   * Create database indexes
   */
  async createIndexes() {
    try {
      const User = require('../models/User');
      const Role = require('../models/Role');
      const Session = require('../models/Session');

      // Ensure indexes are created
      await User.createIndexes();
      await Role.createIndexes();
      await Session.createIndexes();

      logger.info('Database indexes created successfully');
    } catch (error) {
      logger.error('Error creating database indexes:', error);
    }
  }

  /**
   * Backup database
   */
  async backup(backupPath) {
    try {
      // This would typically use mongodump or similar
      // For now, just log the intent
      logger.info(`Database backup requested to: ${backupPath}`);
      // Implementation would depend on deployment environment
    } catch (error) {
      logger.error('Error backing up database:', error);
      throw error;
    }
  }

  /**
   * Get database health information
   */
  async getHealthInfo() {
    try {
      const connection = mongoose.connection;
      const db = connection.db;
      
      // Get database stats
      const stats = await db.stats();
      
      // Get collection stats
      const collections = {};
      for (const collectionName of Object.keys(connection.collections)) {
        try {
          const collection = db.collection(collectionName);
          const collStats = await collection.stats();
          collections[collectionName] = {
            count: collStats.count,
            size: collStats.size,
            avgObjSize: collStats.avgObjSize
          };
        } catch (error) {
          // Collection might not exist yet
          collections[collectionName] = { count: 0, size: 0, avgObjSize: 0 };
        }
      }

      return {
        connected: this.isHealthy(),
        readyState: connection.readyState,
        host: connection.host,
        port: connection.port,
        database: connection.name,
        stats: {
          collections: stats.collections,
          objects: stats.objects,
          dataSize: stats.dataSize,
          storageSize: stats.storageSize,
          indexes: stats.indexes,
          indexSize: stats.indexSize
        },
        collections
      };
    } catch (error) {
      logger.error('Error getting database health info:', error);
      return {
        connected: false,
        error: error.message
      };
    }
  }
}

// Create singleton instance
const databaseConnection = new DatabaseConnection();

// Export connection methods
module.exports = {
  connectDatabase: () => databaseConnection.connect(),
  disconnectDatabase: () => databaseConnection.disconnect(),
  isDatabaseHealthy: () => databaseConnection.isHealthy(),
  getDatabaseStats: () => databaseConnection.getStats(),
  getDatabaseHealth: () => databaseConnection.getHealthInfo(),
  cleanupDatabase: () => databaseConnection.cleanup(),
  createDatabaseIndexes: () => databaseConnection.createIndexes(),
  backupDatabase: (path) => databaseConnection.backup(path)
};

