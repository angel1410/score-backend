// src/structs.rs
use sqlx::postgres::PgPool;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Clone)]
pub struct AppState {
    pub pool_pg: PgPool,
    pub jwt_secret: String,
    pub login_attempts: Arc<Mutex<HashMap<String, AttemptTracker>>>,
    pub captcha_store: Arc<Mutex<HashMap<String, String>>>,
}

#[derive(Clone)]
pub struct AttemptTracker {
    pub count: u32,
    pub last_attempt: DateTime<Utc>,
}