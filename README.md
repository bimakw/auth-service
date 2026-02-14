# Auth Service

Authentication service with JWT, Google OAuth2, TOTP (2FA), and Argon2 password hashing. Built with Rust + Actix-web + PostgreSQL + Redis.

## Running

```bash
cp .env.example .env
make docker-up
make dev
```

## Endpoints

**Auth**: register, login, refresh, logout, me, change-password, forgot/reset-password

**OAuth**: Google sign-in via `/api/oauth/google`

**2FA (TOTP)**: setup, verify-setup, verify, status, disable, backup-codes

**Health**: `GET /health`

See `.env.example` for config (JWT secret, token expiration, Google OAuth, Redis, etc).

## Testing

```bash
cargo test
```

## License

MIT
