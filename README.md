# AuthX - Pluggable Authentication & Authorization System

A comprehensive, scalable, and modular authentication system built with Node.js that serves as a powerful Auth0 alternative. AuthX provides enterprise-grade authentication and authorization capabilities with a pluggable architecture that supports multiple authentication strategies out of the box.

## 🚀 Features

### Core Authentication Mechanisms
- ✅ **JWT-based Authentication** - Stateless API authentication
- ✅ **Local Authentication** - Email/password with bcrypt
- ✅ **OAuth2 Integration** - Google, GitHub, and extensible for other providers
- ✅ **SAML SSO** - Enterprise single sign-on
- ✅ **LDAP Authentication** - Active Directory integration
- 🔄 **Magic Link Authentication** - Passwordless login (coming soon)
- 🔄 **OTP/MFA Support** - Time-based and SMS OTP (coming soon)
- 🔄 **WebAuthn** - Biometric and hardware key authentication (coming soon)

### Security & Compliance
- 🔒 **Comprehensive Security Headers** - XSS, CSRF, and injection protection
- 🛡️ **Rate Limiting** - Brute force protection with Redis backing
- 📊 **Audit Logging** - Complete authentication event tracking
- 🔐 **Password Security** - Configurable strength requirements and history
- 🚫 **Account Lockout** - Automatic protection against failed attempts
- 🔍 **Input Sanitization** - SQL/NoSQL injection prevention

### Authorization & RBAC
- 👥 **Role-Based Access Control** - Hierarchical role system
- 🎯 **Permission Management** - Granular permission control
- 🏢 **Multi-tenant Support** - Organization-level isolation
- 📋 **Policy-Based Authorization** - Flexible access control policies

### Developer Experience
- 🔌 **Pluggable Architecture** - Easy to extend with new strategies
- 📚 **Comprehensive API** - RESTful endpoints for all operations
- 🔧 **Environment Configuration** - Flexible config management
- 📖 **Extensive Documentation** - Clear setup and usage guides
- 🧪 **Testing Support** - Built-in test utilities

### Enterprise Features
- 📈 **Scalable Design** - Horizontal scaling support
- 🗄️ **Database Flexibility** - MongoDB with Redis caching
- 📊 **Monitoring & Analytics** - Built-in metrics and health checks
- 🔄 **Token Management** - Refresh tokens and revocation
- 📧 **Email Integration** - Verification and notification system

## 🏗️ Architecture

AuthX follows a modular, strategy-based architecture that allows for easy extension and customization:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │    │   Admin Panel   │    │   External IDP  │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                        AuthX API Gateway                        │
├─────────────────────────────────────────────────────────────────┤
│  Authentication Routes  │  User Management  │  Admin Routes     │
├─────────────────────────────────────────────────────────────────┤
│                    Strategy Registry                            │
├─────────────────────────────────────────────────────────────────┤
│  JWT    │  Local  │  OAuth2  │  SAML  │  LDAP  │  Custom...    │
├─────────────────────────────────────────────────────────────────┤
│              Authorization & Permission Engine                  │
├─────────────────────────────────────────────────────────────────┤
│  User Service  │  Token Service  │  Audit Service  │  Email     │
├─────────────────────────────────────────────────────────────────┤
│              Security & Rate Limiting Layer                     │
├─────────────────────────────────────────────────────────────────┤
│                    Database Layer                               │
│              MongoDB (Users, Roles, Permissions)               │
│              Redis (Sessions, Cache, Rate Limits)              │
└─────────────────────────────────────────────────────────────────┘
```

## 📦 Installation

### Prerequisites
- Node.js 16+ 
- MongoDB 4.4+
- Redis 6+ (optional but recommended)

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/your-org/authx.git
cd authx
```

2. **Install dependencies**
```bash
npm install
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Start the services**
```bash
# Start MongoDB and Redis (if using Docker)
docker-compose up -d mongodb redis

# Start AuthX
npm run dev
```

5. **Verify installation**
```bash
curl http://localhost:3000/health
```

## ⚙️ Configuration

AuthX uses environment variables for configuration. Copy `.env.example` to `.env` and customize:

### Essential Configuration
```env
# Server
NODE_ENV=development
PORT=3000

# Database
MONGODB_URI=mongodb://localhost:27017/authx
REDIS_URL=redis://localhost:6379

# JWT Secrets (CHANGE IN PRODUCTION!)
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key

# Session Secret
SESSION_SECRET=your-super-secret-session-key
```

### OAuth2 Providers
```env
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth  
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

### Enterprise Features
```env
# SAML SSO
SAML_ENTRY_POINT=https://your-idp.com/sso/saml
SAML_CERT=-----BEGIN CERTIFICATE-----...

# LDAP
LDAP_URL=ldap://your-ldap-server.com:389
LDAP_BIND_DN=cn=admin,dc=example,dc=com
LDAP_BIND_CREDENTIALS=your-ldap-password
```

## 🔌 API Usage

### Authentication

#### Register a new user
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePassword123",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

#### Login with email/password
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securePassword123"
  }'
```

#### Access protected resources
```bash
curl -X GET http://localhost:3000/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### OAuth2 Authentication

#### Google OAuth
```bash
# Redirect user to:
GET http://localhost:3000/auth/google

# Handle callback:
GET http://localhost:3000/auth/google/callback
```

#### GitHub OAuth
```bash
# Redirect user to:
GET http://localhost:3000/auth/github

# Handle callback:
GET http://localhost:3000/auth/github/callback
```

### Token Management

#### Refresh access token
```bash
curl -X POST http://localhost:3000/auth/token/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

#### Verify token
```bash
curl -X POST http://localhost:3000/auth/token/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_JWT_TOKEN"
  }'
```

## 🔧 Extending AuthX

### Adding a Custom Authentication Strategy

1. **Create strategy class**
```javascript
// auth/strategies/customStrategy.js
const AuthStrategy = require('../interfaces/AuthStrategy');

class CustomAuthStrategy extends AuthStrategy {
  constructor() {
    super('custom', { enabled: true, priority: 50 });
  }

  async initialize() {
    // Initialize your strategy
  }

  validateConfig() {
    // Validate configuration
    return true;
  }

  getType() {
    return 'custom';
  }

  // Implement other required methods...
}

module.exports = CustomAuthStrategy;
```

2. **Register the strategy**
```javascript
// The strategy will be auto-discovered and registered
// Or manually register:
const strategyRegistry = require('./auth/strategyRegistry');
const CustomStrategy = require('./auth/strategies/customStrategy');

const customStrategy = new CustomStrategy();
await strategyRegistry.register(customStrategy);
```

### Adding Custom Middleware

```javascript
// middleware/customAuth.js
const customAuthMiddleware = (req, res, next) => {
  // Your custom authentication logic
  next();
};

module.exports = customAuthMiddleware;
```

## 🛡️ Security Features

### Rate Limiting
- **Global**: 100 requests per 15 minutes per IP
- **Login**: 5 attempts per 15 minutes per email/IP
- **Registration**: 3 registrations per hour per IP
- **Password Reset**: 5 requests per hour per email

### Password Security
- Configurable minimum length (default: 8 characters)
- Requires uppercase, lowercase, numbers, and symbols
- Password history tracking (prevents reuse of last 5 passwords)
- Bcrypt hashing with configurable rounds

### Account Protection
- Account lockout after 5 failed login attempts
- Automatic unlock after 2 hours
- Login attempt tracking and audit logging

### Input Validation
- SQL injection prevention
- NoSQL injection prevention  
- XSS protection
- CSRF protection
- Request size limiting

## 📊 Monitoring & Analytics

### Health Checks
```bash
# Basic health check
GET /health

# Detailed admin health check  
GET /admin/health
```

### System Statistics
```bash
# Get system stats (admin only)
GET /admin/stats
```

### Audit Logs
All authentication events are logged with:
- User identification
- IP address and user agent
- Timestamp and outcome
- Strategy used
- Failure reasons

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run with coverage
npm run test:coverage
```

## 📈 Performance & Scaling

### Horizontal Scaling
- Stateless JWT authentication
- Redis-backed session storage
- Database connection pooling
- Load balancer friendly

### Caching Strategy
- Redis for session storage
- Token blacklisting
- Rate limit counters
- User permission caching

### Database Optimization
- Proper indexing on user lookup fields
- Connection pooling
- Query optimization
- Aggregation pipelines for analytics

## 🔒 Production Deployment

### Security Checklist
- [ ] Change all default secrets
- [ ] Enable HTTPS/TLS
- [ ] Configure proper CORS origins
- [ ] Set up rate limiting
- [ ] Enable audit logging
- [ ] Configure backup strategy
- [ ] Set up monitoring alerts

### Environment Variables
```env
NODE_ENV=production
JWT_SECRET=your-production-jwt-secret
SESSION_SECRET=your-production-session-secret
MONGODB_URI=mongodb://your-production-db
REDIS_URL=redis://your-production-redis
```

### Docker Deployment
```bash
# Build image
docker build -t authx .

# Run container
docker run -d \
  --name authx \
  -p 3000:3000 \
  --env-file .env.production \
  authx
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://authx-docs.example.com)
- 💬 [Discord Community](https://discord.gg/authx)
- 🐛 [Issue Tracker](https://github.com/your-org/authx/issues)
- 📧 [Email Support](mailto:support@authx.com)

## 🗺️ Roadmap

### v1.1 (Next Release)
- [ ] Magic Link authentication
- [ ] OTP/TOTP support
- [ ] WebAuthn implementation
- [ ] Admin dashboard UI
- [ ] Email templates

### v1.2 (Future)
- [ ] Multi-tenant architecture
- [ ] Advanced analytics
- [ ] API rate limiting per user
- [ ] Custom branding support
- [ ] Webhook system

### v2.0 (Long-term)
- [ ] GraphQL API
- [ ] Microservices architecture
- [ ] Advanced fraud detection
- [ ] Machine learning insights
- [ ] Mobile SDK

---

**AuthX** - Built with ❤️ for developers who need enterprise-grade authentication without the complexity.

