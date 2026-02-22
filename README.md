# Auth Service

[![CI](https://img.shields.io/github/actions/workflow/status/bimakw/auth-service/ci.yml?branch=main)](https://github.com/bimakw/auth-service/actions)

Authentication microservice with JWT, Google OAuth2, TOTP two-factor auth, role-based access control, and audit logging. Built with Rust (Actix-web), PostgreSQL, and Redis.

## Features

- **JWT Auth** — access + refresh token rotation with configurable expiry
- **Google OAuth2** — sign-in via Google with automatic account linking
- **TOTP 2FA** — setup, verify, backup codes, disable
- **Password Security** — Argon2id hashing, forgot/reset flow, change password
- **RBAC** — role-based access control middleware
- **Audit Logging** — tracks auth events (login, logout, password change, 2FA)
- **Rate Limiting** — Redis-backed per-IP rate limiter on auth endpoints

## Stack

| Component | Tech |
|-----------|------|
| Language | Rust 1.75+ |
| Framework | Actix-web 4 |
| Database | PostgreSQL 15 |
| Cache | Redis 7 |
| Auth | JWT (RS256), Argon2id, TOTP |
| Testing | cargo test + testcontainers |

## Running

```bash
cp .env.example .env
make docker-up       # postgres + redis
make dev             # or: cargo run
```

## Endpoints

| Group | Routes |
|-------|--------|
| **Auth** | register, login, refresh, logout, me, change-password, forgot/reset-password |
| **OAuth** | `GET /api/oauth/google` → Google sign-in |
| **2FA** | setup, verify-setup, verify, status, disable, backup-codes |
| **Health** | `GET /health` |

See `.env.example` for all configuration options.

## Project Structure

```
src/
  auth/          JWT generation, validation, middleware
  handlers/      HTTP request handlers
  models/        domain models + DTOs
  repository/    database queries (sqlx)
  services/      business logic
  middleware/     RBAC, rate limiting, audit
migrations/      SQL migrations
tests/           integration tests
```

## Testing

```bash
cargo test
```

## License

MIT
