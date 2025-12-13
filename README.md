# Auth Service

A robust authentication service built with Rust and Actix-web, featuring JWT authentication, Google OAuth2, and PostgreSQL storage.

## Features

- User registration and login with email/password
- JWT-based authentication (access & refresh tokens)
- **Two-Factor Authentication (TOTP)** with backup codes
- Google OAuth2 integration
- Password hashing with Argon2
- Role-based access control
- Docker support

## Tech Stack

- **Language:** Rust
- **Framework:** Actix-web
- **Database:** PostgreSQL
- **Cache:** Redis
- **Authentication:** JWT, OAuth2, TOTP
- **Password Hashing:** Argon2

## API Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/auth/register` | Register new user | No |
| POST | `/api/auth/login` | Login with email/password | No |
| POST | `/api/auth/refresh` | Refresh access token | No |
| POST | `/api/auth/logout` | Logout user | Yes |
| GET | `/api/auth/me` | Get current user profile | Yes |
| PUT | `/api/auth/change-password` | Change password | Yes |
| POST | `/api/auth/forgot-password` | Request password reset | No |
| POST | `/api/auth/reset-password` | Reset password with token | No |
| GET | `/api/oauth/google` | Redirect to Google OAuth | No |
| GET | `/api/oauth/google/callback` | Google OAuth callback | No |
| GET | `/health` | Health check | No |

### Two-Factor Authentication (2FA/TOTP)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/auth/totp/setup` | Start 2FA setup, get QR code | Yes |
| POST | `/api/auth/totp/verify-setup` | Confirm 2FA setup with code | Yes |
| POST | `/api/auth/totp/verify` | Verify TOTP code during login | Temp Token |
| GET | `/api/auth/totp/status` | Check 2FA status | Yes |
| POST | `/api/auth/totp/disable` | Disable 2FA | Yes |
| POST | `/api/auth/totp/backup-codes` | Regenerate backup codes | Yes |

## Getting Started

### Prerequisites

- Rust 1.75+
- Docker & Docker Compose
- PostgreSQL 16+
- Redis 7+

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/auth-service.git
cd auth-service
```

2. Copy environment file:
```bash
cp .env.example .env
```

3. Update `.env` with your configuration

4. Start dependencies with Docker:
```bash
make docker-up
```

5. Run the application:
```bash
make dev
```

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Server host | `127.0.0.1` |
| `PORT` | Server port | `8080` |
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `JWT_SECRET` | Secret key for JWT | - |
| `JWT_ACCESS_EXPIRATION` | Access token expiration (seconds) | `900` |
| `JWT_REFRESH_EXPIRATION` | Refresh token expiration (seconds) | `604800` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - |
| `GOOGLE_REDIRECT_URL` | Google OAuth redirect URL | - |
| `FRONTEND_URL` | Frontend URL for CORS | `http://localhost:3000` |
| `TOTP_ISSUER` | Issuer name for TOTP (shown in authenticator apps) | `AuthService` |

## API Usage Examples

### Register

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "name": "John Doe"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

### Get Profile (Protected)

```bash
curl -X GET http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer <access_token>"
```

### Refresh Token

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<refresh_token>"
  }'
```

### Two-Factor Authentication

#### Enable 2FA

```bash
# Step 1: Start 2FA setup (get QR code)
curl -X POST http://localhost:8080/api/auth/totp/setup \
  -H "Authorization: Bearer <access_token>"

# Step 2: Verify setup with code from authenticator app
curl -X POST http://localhost:8080/api/auth/totp/verify-setup \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

#### Login with 2FA

```bash
# Step 1: Login (returns temp_token if 2FA enabled)
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Response: {"status": "2fa_required", "temp_token": "...", ...}

# Step 2: Verify TOTP code
curl -X POST http://localhost:8080/api/auth/totp/verify \
  -H "Content-Type: application/json" \
  -d '{"temp_token": "<temp_token>", "code": "123456"}'
```

#### Check 2FA Status

```bash
curl -X GET http://localhost:8080/api/auth/totp/status \
  -H "Authorization: Bearer <access_token>"
```

## Project Structure

```
auth-service/
├── Cargo.toml
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── migrations/
│   ├── 001_create_users_table.sql
│   └── 002_add_totp.sql
└── src/
    ├── main.rs
    ├── lib.rs
    ├── config/
    ├── db/
    ├── errors/
    ├── handlers/
    ├── middleware/
    ├── models/
    ├── services/
    └── utils/
```

## Development

```bash
# Run in development mode
make dev

# Run tests
make test

# Format code
make fmt

# Run linter
make lint

# Build for production
make build
```

## License

MIT License
