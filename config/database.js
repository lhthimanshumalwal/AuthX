const mongoose = require('mongoose');
const redis = require('redis');
const config = require('./config');
const logger = require('../utils/logger');

class DatabaseManager {
  constructor() {
    this.mongoConnection = null;
    this.redisClient = null;
    this.isConnected = false;
  }

  /**
   * Initialize all database connections
   */
  async connect() {
    try {
      await this.connectMongoDB();
      await this.connectRedis();
      this.isConnected = true;
      logger.info('All database connections established successfully');
    } catch (error) {
      logger.error('Failed to establish database connections:', error);
      throw error;
    }
  }

  /**
   * Connect to MongoDB
   */
  async connectMongoDB() {
    try {
      this.mongoConnection = await mongoose.connect(
        config.database.mongodb.uri,
        config.database.mongodb.options
      );

      // Set up MongoDB event listeners
      mongoose.connection.on('connected', () => {
        logger.info('MongoDB connected successfully');
      });

      mongoose.connection.on('error', (error) => {
        logger.error('MongoDB connection error:', error);
      });

      mongoose.connection.on('disconnected', () => {
        logger.warn('MongoDB disconnected');
      });

      // Graceful shutdown
      process.on('SIGINT', async () => {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed through app termination');
        process.exit(0);
      });

      return this.mongoConnection;
    } catch (error) {
      logger.error('MongoDB connection failed:', error);
      throw error;
    }
  }

  /**
   * Connect to Redis
   */
  async connectRedis() {
    try {
      this.redisClient = redis.createClient({
        url: config.database.redis.url,
        ...config.database.redis.options
      });

      // Set up Redis event listeners
      this.redisClient.on('connect', () => {
        logger.info('Redis client connected');
      });

      this.redisClient.on('ready', () => {
        logger.info('Redis client ready');
      });

      this.redisClient.on('error', (error) => {
        logger.error('Redis client error:', error);
      });

      this.redisClient.on('end', () => {
        logger.warn('Redis client disconnected');
      });

      await this.redisClient.connect();
      return this.redisClient;
    } catch (error) {
      logger.error('Redis connection failed:', error);
      // Redis is optional, so we'll continue without it
      logger.warn('Continuing without Redis - some features may be limited');
      return null;
    }
  }

  /**
   * Disconnect from all databases
   */
  async disconnect() {
    try {
      if (this.mongoConnection) {
        await mongoose.connection.close();
        logger.info('MongoDB connection closed');
      }

      if (this.redisClient) {
        await this.redisClient.quit();
        logger.info('Redis connection closed');
      }

      this.isConnected = false;
    } catch (error) {
      logger.error('Error closing database connections:', error);
      throw error;
    }
  }

  /**
   * Get MongoDB connection
   */
  getMongoConnection() {
    if (!this.mongoConnection) {
      throw new Error('MongoDB not connected');
    }
    return this.mongoConnection;
  }

  /**
   * Get Redis client
   */
  getRedisClient() {
    return this.redisClient; // Can be null if Redis is not available
  }

  /**
   * Check if databases are connected
   */
  isHealthy() {
    const mongoHealthy = mongoose.connection.readyState === 1;
    const redisHealthy = !this.redisClient || this.redisClient.isReady;
    
    return {
      mongodb: mongoHealthy,
      redis: redisHealthy,
      overall: mongoHealthy && redisHealthy
    };
  }

  /**
   * Get database statistics
   */
  async getStats() {
    const stats = {
      mongodb: {},
      redis: {}
    };

    try {
      // MongoDB stats
      if (mongoose.connection.readyState === 1) {
        const db = mongoose.connection.db;
        const mongoStats = await db.stats();
        stats.mongodb = {
          connected: true,
          collections: mongoStats.collections,
          dataSize: mongoStats.dataSize,
          indexSize: mongoStats.indexSize,
          storageSize: mongoStats.storageSize
        };
      } else {
        stats.mongodb = { connected: false };
      }

      // Redis stats
      if (this.redisClient && this.redisClient.isReady) {
        const redisInfo = await this.redisClient.info();
        const lines = redisInfo.split('\r\n');
        const redisStats = {};
        
        lines.forEach(line => {
          if (line.includes(':')) {
            const [key, value] = line.split(':');
            redisStats[key] = value;
          }
        });

        stats.redis = {
          connected: true,
          version: redisStats.redis_version,
          uptime: redisStats.uptime_in_seconds,
          connectedClients: redisStats.connected_clients,
          usedMemory: redisStats.used_memory_human,
          totalCommandsProcessed: redisStats.total_commands_processed
        };
      } else {
        stats.redis = { connected: false };
      }
    } catch (error) {
      logger.error('Error getting database stats:', error);
    }

    return stats;
  }
}

// Create singleton instance
const databaseManager = new DatabaseManager();

module.exports = databaseManager;

