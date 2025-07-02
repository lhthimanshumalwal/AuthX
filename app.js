const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoose = require('mongoose');
const passport = require('passport');

// Import configuration
const config = require('./config/config');

// Import utilities and services
const logger = require('./utils/logger');
const { connectDatabase } = require('./utils/database');

// Import middleware
const rateLimiter = require('./middleware/rateLimiter');
const auditLogger = require('./middleware/auditLogger');

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

  async initialize() {
    try {
      // Validate configuration
      config.validate();
      
      // Connect to database
      await connectDatabase();
      
      // Setup middleware
      this.setupMiddleware();
      
      // Setup routes
      this.setupRoutes();
      
      // Setup error handling
      this.setupErrorHandling();
      
      logger.info('AuthX server initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize AuthX server:', error);
      process.exit(1);
    }
  }

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
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    }));

    // CORS
    this.app.use(cors(config.cors));

    // Logging
    if (config.server.env !== 'test') {
      this.app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
    }

    // Body parsing
    this.app.use(bodyParser.json({ limit: '10mb' }));
    this.app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

    // Rate limiting
    this.app.use('/api/', rateLimiter.general);
    this.app.use('/auth/login', rateLimiter.login);
    this.app.use('/auth/register', rateLimiter.register);

    // Session configuration
    this.app.use(session({
      secret: config.session.secret,
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        mongoUrl: config.database.mongodb.uri,
        touchAfter: 24 * 3600 // lazy session update
      }),
      cookie: {
        secure: config.session.secure,
        httpOnly: config.session.httpOnly,
        maxAge: config.session.maxAge,
        sameSite: config.session.sameSite
      }
    }));

    // Passport middleware
    this.app.use(passport.initialize());
    this.app.use(passport.session());

    // Audit logging
    if (config.logging.enableAuditLogging) {
      this.app.use(auditLogger);
    }

    // Request context middleware
    this.app.use((req, res, next) => {
      req.context = {
        requestId: require('uuid').v4(),
        timestamp: new Date(),
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      };
      next();
    });
  }

  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: require('./package.json').version,
        environment: config.server.env
      });
    });

    // API routes
    this.app.use('/auth', authRoutes);
    this.app.use('/api/users', userRoutes);
    this.app.use('/api/admin', adminRoutes);

    // Root endpoint
    this.app.get('/', (req, res) => {
      res.json({
        message: 'Welcome to AuthX - Scalable Authentication System',
        version: require('./package.json').version,
        documentation: '/api/docs',
        health: '/health'
      });
    });

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Not Found',
        message: 'The requested resource was not found',
        path: req.originalUrl
      });
    });
  }

  setupErrorHandling() {
    // Global error handler
    this.app.use((error, req, res, next) => {
      logger.error('Unhandled error:', {
        error: error.message,
        stack: error.stack,
        requestId: req.context?.requestId,
        url: req.url,
        method: req.method,
        ip: req.ip
      });

      // Don't leak error details in production
      const isDevelopment = config.server.env === 'development';
      
      res.status(error.status || 500).json({
        error: error.name || 'Internal Server Error',
        message: isDevelopment ? error.message : 'An unexpected error occurred',
        ...(isDevelopment && { stack: error.stack }),
        requestId: req.context?.requestId
      });
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      this.gracefulShutdown('UNCAUGHT_EXCEPTION');
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
      this.gracefulShutdown('UNHANDLED_REJECTION');
    });

    // Handle SIGTERM
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received');
      this.gracefulShutdown('SIGTERM');
    });

    // Handle SIGINT
    process.on('SIGINT', () => {
      logger.info('SIGINT received');
      this.gracefulShutdown('SIGINT');
    });
  }

  async start() {
    await this.initialize();
    
    this.server = this.app.listen(config.server.port, () => {
      logger.info(`AuthX server running on port ${config.server.port} in ${config.server.env} mode`);
      logger.info(`Health check available at http://localhost:${config.server.port}/health`);
    });

    return this.server;
  }

  async gracefulShutdown(signal) {
    logger.info(`${signal} received, starting graceful shutdown...`);
    
    if (this.server) {
      this.server.close(async () => {
        logger.info('HTTP server closed');
        
        try {
          await mongoose.connection.close();
          logger.info('Database connection closed');
        } catch (error) {
          logger.error('Error closing database connection:', error);
        }
        
        logger.info('Graceful shutdown completed');
        process.exit(0);
      });
    } else {
      process.exit(0);
    }
  }
}

// Start server if this file is run directly
if (require.main === module) {
  const server = new AuthXServer();
  server.start().catch(error => {
    logger.error('Failed to start server:', error);
    process.exit(1);
  });
}

module.exports = AuthXServer;

