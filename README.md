# AuthX - Scalable Authentication System

A comprehensive, production-ready authentication system built with Node.js and Express.js that serves as a powerful alternative to Auth0. AuthX provides multiple authentication mechanisms, role-based access control, and enterprise-grade security features.

## 🚀 Features

### Core Authentication
- ✅ **JWT-based Authentication** - Stateless API authentication with access/refresh tokens
- ✅ **Email/Password Login** - Traditional authentication with bcrypt password hashing
- ✅ **OAuth2 Integration** - Google, GitHub, and other OAuth providers
- ✅ **SAML SSO** - Enterprise single sign-on with SAML 2.0
- ✅ **LDAP/Active Directory** - Enterprise directory integration
- ✅ **Magic Link Authentication** - Passwordless login via email links
- ✅ **Two-Factor Authentication** - TOTP (Google Authenticator) with backup codes

### Security & Compliance
- 🔒 **Role-Based Access Control (RBAC)** - Flexible permission system
- 🛡️ **Rate Limiting** - Brute force protection and API rate limiting
- 📊 **Audit Logging** - Comprehensive security event tracking
- 🔐 **Session Management** - Device tracking and session control
- 🚫 **Token Blacklisting** - Secure token revocation
- 📧 **Email Verification** - Account verification workflows
- 🔄 **Password Reset** - Secure password recovery

### Enterprise Features
- 👥 **User Management** - Complete user lifecycle management
- 🏢 **Multi-tenant Support** - Organization and role hierarchies
- 📈 **Analytics & Monitoring** - Authentication metrics and health checks
- 🔧 **Admin Dashboard** - Web-based administration interface
- 📤 **Data Export** - User and audit data export capabilities
- 🔌 **Pluggable Architecture** - Easy to extend with custom strategies

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Authentication Strategies](#authentication-strategies)
- [API Documentation](#api-documentation)
- [Security Features](#security-features)
- [Deployment](#deployment)
- [Contributing](#contributing)

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ 
- MongoDB 4.4+
- Redis (optional, for session storage)
- SMTP server (for email features)

### Installation

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

4. **Start the server**
```bash
npm run dev
```

The server will start on `http://localhost:3000`

### Basic Usage

1. **Register a new user**
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

2. **Login**
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

3. **Access protected routes**
```bash
curl -X GET http://localhost:3000/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with the following configuration:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database
MONGODB_URI=mongodb://localhost:27017/authx
REDIS_URL=redis://localhost:6379

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=24h
JWT_REFRESH_SECRET=your-super-secret-refresh-key
JWT_REFRESH_EXPIRES_IN=7d

# OAuth2 Providers
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# SAML Configuration
SAML_ENTRY_POINT=https://your-idp.com/sso/saml
SAML_ISSUER=authx-app
SAML_CERT_PATH=./certs/saml-cert.pem

# LDAP Configuration
LDAP_URL=ldap://localhost:389
LDAP_BIND_DN=cn=admin,dc=example,dc=com
LDAP_BIND_CREDENTIALS=admin-password

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Security
BCRYPT_ROUNDS=12
REQUIRE_EMAIL_VERIFICATION=true
ENABLE_2FA=true
```

### Advanced Configuration

The system supports extensive configuration through the `config/config.js` file:

- **Rate Limiting**: Customize rate limits for different endpoints
- **Security Policies**: Password requirements, session timeouts
- **Feature Flags**: Enable/disable specific authentication methods
- **Audit Settings**: Configure logging and retention policies

## 🔐 Authentication Strategies

### 1. JWT Authentication

Stateless authentication using JSON Web Tokens:

```javascript
// Include JWT token in requests
headers: {
  'Authorization': 'Bearer ' + accessToken
}
```

### 2. OAuth2 (Google, GitHub)

Social login integration:

```bash
# Initiate OAuth flow
GET /auth/google
GET /auth/github

# Handle callback
GET /auth/google/callback
GET /auth/github/callback
```

### 3. SAML SSO

Enterprise single sign-on:

```bash
# Initiate SAML authentication
POST /auth/saml

# Handle SAML response
POST /auth/saml/callback
```

### 4. LDAP/Active Directory

Directory service integration:

```bash
POST /auth/ldap
Content-Type: application/json

{
  "username": "john.doe",
  "password": "password"
}
```

### 5. Magic Link

Passwordless authentication:

```bash
# Request magic link
POST /auth/magic-link/request
{
  "email": "user@example.com"
}

# Verify magic link
GET /auth/magic-link/verify?token=MAGIC_TOKEN
```

### 6. Two-Factor Authentication

TOTP-based 2FA:

```bash
# Setup 2FA
POST /auth/2fa/setup

# Verify setup
POST /auth/2fa/verify-setup
{
  "token": "123456"
}

# Verify during login
POST /auth/2fa/verify
{
  "userId": "user_id",
  "token": "123456"
}
```

## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | Email/password login |
| POST | `/auth/logout` | Logout user |
| POST | `/auth/refresh` | Refresh access token |
| GET | `/auth/me` | Get current user |
| POST | `/auth/verify-email` | Verify email address |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Reset password |

### User Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users/profile` | Get user profile |
| PUT | `/api/users/profile` | Update user profile |
| POST | `/api/users/change-password` | Change password |
| GET | `/api/users` | List users (Admin) |
| PUT | `/api/users/:id` | Update user (Admin) |
| DELETE | `/api/users/:id` | Delete user (Admin) |

### Admin Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/dashboard` | Admin dashboard data |
| GET | `/api/admin/users` | Advanced user listing |
| GET | `/api/admin/audit-logs` | Audit log access |
| GET | `/api/admin/system-health` | System health check |
| POST | `/api/admin/test-email` | Test email configuration |

### Response Format

All API responses follow a consistent format:

```json
{
  "message": "Success message",
  "user": {
    "id": "user_id",
    "email": "user@example.com",
    "profile": { ... },
    "roles": ["user"],
    "status": "active"
  },
  "tokens": {
    "accessToken": "jwt_token",
    "refreshToken": "refresh_token",
    "tokenType": "Bearer",
    "expiresIn": 86400
  }
}
```

Error responses:

```json
{
  "error": "Error Type",
  "message": "Human readable error message",
  "details": [ ... ] // Validation errors if applicable
}
```

## 🛡️ Security Features

### Password Security
- **bcrypt hashing** with configurable rounds
- **Password complexity requirements**
- **Password history** to prevent reuse
- **Secure password reset** with time-limited tokens

### Session Security
- **Device fingerprinting** for session tracking
- **IP address monitoring** for suspicious activity
- **Session timeout** and automatic cleanup
- **Concurrent session limits**

### Rate Limiting
- **Login attempt limiting** to prevent brute force
- **API rate limiting** per user/IP
- **Progressive delays** for repeated failures
- **Whitelist support** for trusted IPs

### Audit & Monitoring
- **Comprehensive audit logging** of all security events
- **Real-time security alerts** for suspicious activity
- **Compliance reporting** for regulatory requirements
- **Data retention policies** for audit logs

## 🏗️ Architecture

### Project Structure

```
authx/
├── app.js                 # Main application entry point
├── config/
│   └── config.js         # Configuration management
├── auth/
│   ├── passport.js       # Passport configuration
│   └── strategies/       # Authentication strategies
├── routes/
│   ├── auth.js          # Authentication routes
│   ├── user.js          # User management routes
│   └── admin.js         # Admin routes
├── middleware/
│   ├── authMiddleware.js # Authentication middleware
│   ├── rateLimiter.js   # Rate limiting
│   └── auditLogger.js   # Audit logging
├── models/
│   ├── User.js          # User model
│   ├── Role.js          # Role model
│   └── Session.js       # Session model
├── services/
│   ├── userService.js   # User business logic
│   ├── emailService.js  # Email service
│   └── auditService.js  # Audit service
└── utils/
    ├── tokenUtils.js    # JWT utilities
    ├── cryptoUtils.js   # Cryptographic utilities
    ├── logger.js        # Logging utilities
    └── database.js      # Database utilities
```

### Database Schema

#### Users Collection
```javascript
{
  _id: ObjectId,
  email: String,
  username: String,
  password: String, // bcrypt hashed
  profile: {
    firstName: String,
    lastName: String,
    displayName: String,
    avatar: String,
    // ... other profile fields
  },
  roles: [ObjectId], // References to Role documents
  status: String, // active, inactive, suspended, pending
  emailVerified: Boolean,
  twoFactorAuth: {
    enabled: Boolean,
    secret: String,
    backupCodes: [String]
  },
  authProviders: [String], // local, google, github, saml, ldap
  oauthProviders: {
    google: { id: String, email: String },
    github: { id: String, username: String },
    // ... other providers
  },
  createdAt: Date,
  updatedAt: Date
}
```

#### Roles Collection
```javascript
{
  _id: ObjectId,
  name: String, // unique role name
  displayName: String,
  description: String,
  permissions: [String],
  level: Number, // hierarchy level
  isSystem: Boolean,
  createdAt: Date,
  updatedAt: Date
}
```

## 🚀 Deployment

### Docker Deployment

1. **Build the image**
```bash
docker build -t authx .
```

2. **Run with Docker Compose**
```yaml
version: '3.8'
services:
  authx:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://mongo:27017/authx
    depends_on:
      - mongo
      - redis
  
  mongo:
    image: mongo:5
    volumes:
      - mongo_data:/data/db
  
  redis:
    image: redis:7-alpine

volumes:
  mongo_data:
```

### Production Considerations

1. **Environment Security**
   - Use strong, unique secrets for JWT and sessions
   - Enable HTTPS/TLS in production
   - Configure proper CORS settings
   - Use environment-specific configurations

2. **Database Security**
   - Enable MongoDB authentication
   - Use connection string with credentials
   - Configure proper network security
   - Regular database backups

3. **Monitoring & Logging**
   - Set up log aggregation (ELK stack, Splunk)
   - Configure health check endpoints
   - Monitor authentication metrics
   - Set up alerting for security events

4. **Scaling**
   - Use Redis for session storage in multi-instance deployments
   - Configure load balancer with sticky sessions if needed
   - Monitor performance metrics
   - Implement horizontal scaling strategies

## 🧪 Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### Test Categories

- **Unit Tests**: Individual component testing
- **Integration Tests**: API endpoint testing
- **Security Tests**: Authentication and authorization testing
- **Performance Tests**: Load and stress testing

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Style

- Use ESLint configuration provided
- Follow conventional commit messages
- Add JSDoc comments for new functions
- Maintain test coverage above 80%

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Full API Documentation](docs/API.md)
- **Issues**: [GitHub Issues](https://github.com/your-org/authx/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/authx/discussions)
- **Security**: Report security issues to security@authx.com

## 🙏 Acknowledgments

- [Passport.js](http://www.passportjs.org/) for authentication strategies
- [Express.js](https://expressjs.com/) for the web framework
- [MongoDB](https://www.mongodb.com/) for the database
- [JWT](https://jwt.io/) for token-based authentication

---

**AuthX** - Built with ❤️ for developers who need enterprise-grade authentication without the complexity.
