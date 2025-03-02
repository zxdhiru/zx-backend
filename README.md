# zx Authentication Service

A centralized authentication service that allows users to log in to websites and apps using "Continue with zx," similar to "Continue with Google." Built with OAuth 2.0 and WebAuthn for secure, passwordless authentication.

## Features

- OAuth 2.0 Authentication
  - Authorization & Token endpoints
  - Refresh token support
  - Secure JWT-based access tokens
- WebAuthn (Passwordless Login)
  - Passkey registration & authentication
  - Public key storage in PostgreSQL
- User Management
  - User registration & login
  - Secure session handling
- Developer API
  - Authentication API (Login, Logout, Refresh Token)
  - OAuth client registration for third-party apps

## Tech Stack

- Backend: Go (Golang)
- Database: PostgreSQL
- Authentication: OAuth 2.0, WebAuthn (passkeys)
- Framework: Fiber
- API Format: RESTful APIs
- Security: JWT-based authentication, OAuth token management

## Prerequisites

- Go 1.21 or higher
- PostgreSQL 14 or higher
- Make (for using Makefile commands)

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/zx-backend.git
   cd zx-backend
   ```

2. Copy the example environment file and configure your settings:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Install dependencies:
   ```bash
   make deps
   ```

4. Start the development server:
   ```bash
   make run
   ```

   For hot reload during development:
   ```bash
   make dev
   ```

## Development Commands

- `make build`: Build the application
- `make run`: Run the application
- `make test`: Run tests
- `make clean`: Clean build artifacts
- `make deps`: Install dependencies
- `make migrate`: Run database migrations
- `make docs`: Generate API documentation
- `make dev`: Run with hot reload
- `make security`: Run security checks

## API Documentation

### OAuth 2.0 Endpoints

- `POST /api/oauth/token`: Generate OAuth tokens
- `POST /api/oauth/authorize`: Authorize client application
- `POST /api/oauth/revoke`: Revoke tokens

### WebAuthn Endpoints

- `POST /api/webauthn/register`: Register WebAuthn passkey
- `POST /api/webauthn/login`: Login with WebAuthn

### User Management

- `POST /api/register`: Register new user
- `POST /api/login`: Authenticate user
- `POST /api/logout`: Logout user
- `POST /api/token/refresh`: Refresh access token

## Security

This project implements several security measures:

- JWT-based authentication
- OAuth 2.0 token management
- WebAuthn passwordless authentication
- CORS protection
- Rate limiting
- Input validation
- Secure session handling

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 