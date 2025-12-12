use sqlx::{postgres::PgPoolOptions, PgPool, Executor};

pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    // Use raw_sql to execute multiple statements
    let migration_sql = include_str!("../../migrations/001_create_users_table.sql");
    pool.execute(migration_sql).await?;

    tracing::info!("Database migrations completed successfully");
    Ok(())
}
