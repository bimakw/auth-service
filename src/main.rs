use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use auth_service::config::Config;
use auth_service::db;
use auth_service::handlers::{auth_routes, health_check, oauth_routes, totp_routes};
use auth_service::services::{AuthService, LockoutService, RateLimiters, ResetService, TokenService, TOTPService};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load .env file
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");
    let server_addr = config.server_addr();

    tracing::info!("Starting Auth Service on {}", server_addr);

    // Create database pool
    let pool = db::create_pool(&config.database_url)
        .await
        .expect("Failed to create database pool");

    // Run migrations
    db::run_migrations(&pool)
        .await
        .expect("Failed to run migrations");

    // Create services
    let auth_service = web::Data::new(AuthService::new(pool.clone()));
    let token_service = web::Data::new(TokenService::new(config.clone()));
    let reset_service = web::Data::new(
        ResetService::new(&config.redis_url).expect("Failed to create reset service")
    );
    let totp_service = web::Data::new(TOTPService::new(pool.clone(), config.clone()));
    let rate_limiters = web::Data::new(
        RateLimiters::new(&config.redis_url).expect("Failed to create rate limiters")
    );
    let lockout_service = web::Data::new(
        LockoutService::with_defaults(&config.redis_url).expect("Failed to create lockout service")
    );
    let config_data = web::Data::new(config.clone());

    // Start HTTP server
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&config.frontend_url)
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec!["Authorization", "Content-Type"])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(tracing_actix_web::TracingLogger::default())
            .app_data(auth_service.clone())
            .app_data(token_service.clone())
            .app_data(reset_service.clone())
            .app_data(totp_service.clone())
            .app_data(rate_limiters.clone())
            .app_data(lockout_service.clone())
            .app_data(config_data.clone())
            .service(health_check)
            .configure(auth_routes)
            .configure(oauth_routes)
            .configure(totp_routes)
    })
    .bind(&server_addr)?
    .run()
    .await
}
