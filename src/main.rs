// src/main.rs
#![allow(non_snake_case)]
use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use dotenvy::dotenv;
use sqlx::postgres::PgPool;
use std::env;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

mod structs {
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
}

mod modules {
    pub mod login;
    pub mod re;
    pub mod ac;
    pub mod users;
    pub mod logging; 

    pub use login::{get_login, get_logout, get_captcha};
    pub use re::{get_movimientos_re, get_elector, get_electores, get_votos_emitir};
    pub use users::{
        get_usuarios, 
        crear_usuario, 
        actualizar_usuario, 
        bloquear_usuario,
        eliminar_usuario,
        reactivar_usuario, 
        carga_masiva, get_roles,
        descargar_plantilla,
    };
    pub use ac::get_usuario_by_ac;
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();
    
    // ✅ Variables Oracle
    let _oracle_user = env::var("ORACLE_USER").expect("ORACLE_USER faltante");
    let _oracle_pass = env::var("ORACLE_PASS").expect("ORACLE_PASS faltante");
    let _oracle_ip = env::var("ORACLE_IP").expect("ORACLE_IP faltante");
    let _oracle_port = env::var("ORACLE_PORT").expect("ORACLE_PORT faltante");
    let _oracle_db = env::var("ORACLE_DB").expect("ORACLE_DB faltante");

    // ✅ Variables principales
    let allowed_origin =
        env::var("ALLOWED_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".to_string());
    let url_pg = env::var("PG_URL").expect("Variable PG_URL faltante");
    let jwt_secret = env::var("JWT_SECRET").expect("Variable JWT_SECRET faltante");

    // ✅ Conexión a PostgreSQL
    let pool_pg = PgPool::connect(&url_pg).await.expect("Error conectando a BD");

    // ✅ Inicializar stores para Rate Limiting y CAPTCHA
    let login_attempts = Arc::new(Mutex::new(HashMap::new()));
    let captcha_store = Arc::new(Mutex::new(HashMap::new()));

    println!("\n🚀 Backend SCORE iniciado");
    println!("========================================");
    println!("📡 Servidor: http://127.0.0.1:9000");
    println!("🔐 JWT: Configurado");
    println!("🛡️  Protección: Honeypot + CAPTCHA + Rate Limiting");
    println!("🌐 CORS: {}", allowed_origin);

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allowed_origin(allowed_origin.as_str())
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
                    .allowed_headers(vec![
                        actix_web::http::header::AUTHORIZATION,
                        actix_web::http::header::ACCEPT,
                        actix_web::http::header::CONTENT_TYPE,
                    ])
                    .max_age(3600)
                    .supports_credentials(),
            )
            .app_data(web::Data::new(structs::AppState {
                pool_pg: pool_pg.clone(),
                jwt_secret: jwt_secret.clone(),
                login_attempts: login_attempts.clone(),
                captcha_store: captcha_store.clone(),
            }))
            .service(
                web::scope("/api")
                    .route("/login", web::post().to(modules::get_login))
                    .route("/logout", web::post().to(modules::get_logout))  // ✅ CORREGIDO
                    .route("/captcha", web::get().to(modules::get_captcha))
                    .route("/get-movimientos-re/{nacionalidad}/{cedula}", web::get().to(modules::get_movimientos_re))
                    .route("/get_elector", web::get().to(modules::get_elector))
                    .route("/get_electores", web::get().to(modules::get_electores))
                    .route("/get_votos_emitir/{nacionalidad}/{cedula}", web::get().to(modules::get_votos_emitir))
                    .route("/usuarios", web::get().to(modules::get_usuarios))
                    .route("/usuarios", web::post().to(modules::crear_usuario))
                    .route("/usuarios/{id}", web::put().to(modules::actualizar_usuario))
                    .route("/usuarios/{id}", web::delete().to(modules::eliminar_usuario))
                    .route("/usuarios/{id}/reactivar", web::put().to(modules::reactivar_usuario))
                    .route("/usuarios/{id}/bloquear", web::put().to(modules::bloquear_usuario))
                    .route("/usuarios/carga-masiva", web::post().to(modules::carga_masiva))
                    .route("/usuarios/plantilla", web::get().to(modules::descargar_plantilla))
                    .route("/get_usuario_by_ac/{nacionalidad}/{cedula}", web::get().to(modules::get_usuario_by_ac))
                    .route("/roles", web::get().to(modules::get_roles)),
            )
    })
    .bind(("127.0.0.1", 9000))?
    .run()
    .await
}