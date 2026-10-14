// src/structs.rs
use sqlx::postgres::PgPool;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Clone, Debug)]
pub struct CaptchaEntry {
    pub answer: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct AppState {
    pub pool_pg: PgPool,
    pub pool_oracle: Arc<oracle::pool::Pool>,
    pub jwt_secret: String,
    pub login_attempts: Arc<Mutex<HashMap<String, AttemptTracker>>>,
    pub captcha_store: Arc<Mutex<HashMap<String, CaptchaEntry>>>,
    pub memory_cache: Arc<Mutex<HashMap<String, (String, DateTime<Utc>)>>>,
}

impl AppState {
    pub fn get_cached(&self, key: &str) -> Option<String> {
        let mut cache = self.memory_cache.lock().ok()?;
        if let Some((val, exp)) = cache.get(key) {
            if *exp > Utc::now() {
                return Some(val.clone());
            } else {
                cache.remove(key);
            }
        }
        None
    }

    pub fn set_cached(&self, key: &str, val: String, ttl_seconds: i64) {
        if let Ok(mut cache) = self.memory_cache.lock() {
            cache.insert(
                key.to_string(),
                (val, Utc::now() + chrono::Duration::seconds(ttl_seconds)),
            );
        }
    }

    pub fn invalidate_cache_prefix(&self, prefix: &str) {
        if let Ok(mut cache) = self.memory_cache.lock() {
            cache.retain(|k, _| !k.starts_with(prefix));
        }
    }
}

#[derive(Clone)]
pub struct AttemptTracker {
    pub count: u32,
    pub last_attempt: DateTime<Utc>,
}

