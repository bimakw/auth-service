# Auth Service

A robust authentication service built with Rust and Actix-web, featuring JWT authentication, Google OAuth2, and PostgreSQL storage.

## Features

- User registration and login with email/password
- JWT-based authentication (access & refresh tokens)
- Google OAuth2 integration
- Password hashing with Argon2
- Role-based access control
- Docker support

## Tech Stack

- **Language:** Rust
- **Framework:** Actix-web
- **Database:** PostgreSQL
- **Cache:** Redis
- **Authentication:** JWT, OAuth2
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
| GET | `/api/oauth/google` | Redirect to Google OAuth | No |
| GET | `/api/oauth/google/callback` | Google OAuth callback | No |
| GET | `/health` | Health check | No |

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

## Project Structure

```
auth-service/
├── Cargo.toml
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── migrations/
│   └── 001_create_users_table.sql
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
