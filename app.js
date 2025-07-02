const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');

// Import configuration and utilities
const config = require('./config/config');
const databaseManager = require('./config/database');
const logger = require('./utils/logger');

// Import middleware
const rateLimiting = require('./middleware/rateLimiting');
const security = require('./middleware/security');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const adminRoutes = require('./routes/admin');

// Import passport configuration
require('./auth/passport');

class AuthXServer {
  constructor() {
    this.app = express();
    this.server = null;
  }

  /**
   * Initialize the server
   */
  async initialize() {
    try {
      // Validate configuration
      config.validate();
      logger.info('Configuration validated successfully');

      // Connect to databases
      await databaseManager.connect();
      logger.info('Database connections established');

      // Setup middleware
      this.setupMiddleware();
      logger.info('Middleware configured');

      // Setup routes
      this.setupRoutes();
      logger.info('Routes configured');

      // Setup error handling
      this.setupErrorHandling();
      logger.info('Error handling configured');

      logger.info('AuthX server initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize server:', error);
      throw error;
    }
  }

  /**
   * Setup middleware
   */
  setupMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
      crossOriginEmbedderPolicy: false
    }));

    // CORS configuration
    this.app.use(cors(config.cors));

    // Body parsing middleware
    this.app.use(bodyParser.json({ limit: '10mb' }));
    this.app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

    // Session configuration
    const sessionConfig = {
      secret: config.session.secret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: config.session.secure,
        httpOnly: config.session.httpOnly,
        maxAge: config.session.maxAge,
        sameSite: config.session.sameSite
      }
    };

    // Use MongoDB for session storage if available
    if (databaseManager.getMongoConnection()) {
      sessionConfig.store = MongoStore.create({
        mongoUrl: config.database.mongodb.uri,
        touchAfter: 24 * 3600 // lazy session update
      });
    }

    this.app.use(session(sessionConfig));

    // Passport middleware
    this.app.use(passport.initialize());
    this.app.use(passport.session());

    // Rate limiting
    this.app.use(rateLimiting.global);

    // Custom security middleware
    this.app.use(security.addSecurityHeaders);
    this.app.use(security.sanitizeInput);

    // Request logging
    this.app.use((req, res, next) => {
      logger.info(`${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user ? req.user.id : null
      });
      next();
    });
  }

  /**
   * Setup routes
   */
  setupRoutes() {
    // Health check endpoint
    this.app.get('/health', async (req, res) => {
      try {
        const dbHealth = databaseManager.isHealthy();
        const health = {
          status: dbHealth.overall ? 'healthy' : 'unhealthy',
          timestamp: new Date().toISOString(),
          version: require('./package.json').version,
          environment: config.server.env,
          databases: dbHealth
        };

        res.status(dbHealth.overall ? 200 : 503).json(health);
      } catch (error) {
        logger.error('Health check failed:', error);
        res.status(503).json({
          status: 'unhealthy',
          timestamp: new Date().toISOString(),
          error: 'Health check failed'
        });
      }
    });

    // API documentation endpoint
    this.app.get('/', (req, res) => {
      res.json({
        name: 'AuthX - Authentication & Authorization System',
        version: require('./package.json').version,
        description: 'A pluggable, scalable authentication system - Auth0 replacement',
        endpoints: {
          health: '/health',
          auth: '/auth/*',
          user: '/user/*',
          admin: '/admin/*'
        },
        documentation: 'https://github.com/your-org/authx#readme'
      });
    });

    // API routes
    this.app.use('/auth', authRoutes);
    this.app.use('/user', userRoutes);
    this.app.use('/admin', adminRoutes);

    // Database stats endpoint (for monitoring)
    this.app.get('/stats', async (req, res) => {
      try {
        const stats = await databaseManager.getStats();
        res.json(stats);
      } catch (error) {
        logger.error('Stats endpoint error:', error);
        res.status(500).json({ error: 'Failed to retrieve stats' });
      }
    });
  }

  /**
   * Setup error handling
   */
  setupErrorHandling() {
    // 404 handler
    this.app.use(notFoundHandler);

    // Global error handler
    this.app.use(errorHandler);
  }

  /**
   * Start the server
   */
  async start() {
    try {
      await this.initialize();

      this.server = this.app.listen(config.server.port, config.server.host, () => {
        logger.info(`AuthX server running on ${config.server.host}:${config.server.port}`);
        logger.info(`Environment: ${config.server.env}`);
        logger.info('Server ready to accept connections');
      });

      // Graceful shutdown handling
      this.setupGracefulShutdown();

      return this.server;
    } catch (error) {
      logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  /**
   * Setup graceful shutdown
   */
  setupGracefulShutdown() {
    const gracefulShutdown = async (signal) => {
      logger.info(`Received ${signal}. Starting graceful shutdown...`);

      if (this.server) {
        this.server.close(async () => {
          logger.info('HTTP server closed');

          try {
            await databaseManager.disconnect();
            logger.info('Database connections closed');
            logger.info('Graceful shutdown completed');
            process.exit(0);
          } catch (error) {
            logger.error('Error during graceful shutdown:', error);
            process.exit(1);
          }
        });
      }

      // Force shutdown after 30 seconds
      setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
      }, 30000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
      gracefulShutdown('unhandledRejection');
    });
  }

  /**
   * Stop the server
   */
  async stop() {
    if (this.server) {
      return new Promise((resolve) => {
        this.server.close(resolve);
      });
    }
  }
}

// Create and export server instance
const authXServer = new AuthXServer();

// Start server if this file is run directly
if (require.main === module) {
  authXServer.start().catch((error) => {
    logger.error('Failed to start AuthX server:', error);
    process.exit(1);
  });
}

module.exports = authXServer;

