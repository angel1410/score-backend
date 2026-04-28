#![allow(non_snake_case)]

use actix_cors::Cors;
use actix_files::Files;
use actix_web::http::header;
use actix_web::{web, App, HttpResponse, HttpServer};
use dotenvy::dotenv;
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

// ✅ Módulo structs externo
mod structs;

// ✅ Módulos
mod modules;
mod utils;

// ✅ Middleware
mod middleware;
use middleware::auth::AuthMiddleware;
use middleware::security_headers::SecurityHeaders;

// =====================================================
// ✅ VISUALIZADOR INLINE DE PDFs PÚBLICOS
// =====================================================
// Esta función permite abrir los PDF en el visor del navegador
// en vez de forzar la descarga.
// =====================================================
async fn ver_pdf(path: web::Path<String>) -> actix_web::Result<HttpResponse> {
    let filename = path.into_inner();

    // ✅ Lista blanca: solo permite estos archivos
    let allowed_files = ["guia_rapida.pdf", "guia_rapida_admin.pdf"];

    if !allowed_files.contains(&filename.as_str()) {
        return Ok(HttpResponse::NotFound().finish());
    }

    let file_path = format!("./files/templates/{}", filename);

    match std::fs::read(&file_path) {
        Ok(bytes) => Ok(HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, "application/pdf"))
            .insert_header((
                header::CONTENT_DISPOSITION,
                format!("inline; filename=\"{}\"", filename),
            ))
            .body(bytes)),
        Err(_) => Ok(HttpResponse::NotFound().finish()),
    }
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
    println!("🛡️ Protección: Honeypot + CAPTCHA + Rate Limiting + Auth middleware");
    println!("🌐 CORS: {}", allowed_origin);
    println!("📁 Archivos públicos: /files -> ./files/templates");
    println!("📄 PDFs inline: /files/guia_rapida.pdf y /files/guia_rapida_admin.pdf");

    HttpServer::new(move || {
        App::new()
            .wrap(SecurityHeaders)
            .wrap(
                Cors::default()
                    .allowed_origin(allowed_origin.as_str())
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
                    .allowed_headers(vec![
                        actix_web::http::header::AUTHORIZATION,
                        actix_web::http::header::ACCEPT,
                        actix_web::http::header::CONTENT_TYPE,
                        actix_web::http::header::CACHE_CONTROL,
                        actix_web::http::header::PRAGMA,
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

            // =====================================================
            // ✅ PDFs PÚBLICOS INLINE
            // =====================================================
            // Estas rutas se abren en el visor del navegador:
            // /files/guia_rapida.pdf
            // /files/guia_rapida_admin.pdf
            //
            // IMPORTANTE:
            // Esta ruta NO pasa por AuthMiddleware.
            // =====================================================
            .route("/files/{filename}", web::get().to(ver_pdf))

            // =====================================================
            // ✅ ARCHIVOS PÚBLICOS GENERALES
            // =====================================================
            // Esto permite acceder públicamente a otros archivos de:
            // ./files/templates
            //
            // Ejemplo:
            // /files/plantilla.xlsx
            //
            // Los PDF anteriores pasan primero por ver_pdf.
            // =====================================================
            .service(
                Files::new("/files", "./files/templates")
                    .use_last_modified(true)
            )

            .service(
                web::scope("/api")
                    // =========================
                    // RUTAS PÚBLICAS
                    // =========================
                    .route("/login", web::post().to(modules::get_login))
                    .route("/captcha", web::get().to(modules::get_captcha))
                    .route(
                        "/verificar/{codigo}",
                        web::get().to(modules::exportacion::verificar_documento),
                    )

                    // =========================
                    // RUTAS PRIVADAS
                    // =========================
                    .service(
                        web::scope("")
                            .wrap(AuthMiddleware)
                            .route("/logout", web::post().to(modules::get_logout))
                            .route(
                                "/get-movimientos-re/{nacionalidad}/{cedula}",
                                web::get().to(modules::get_movimientos_re),
                            )
                            .route("/get_elector", web::get().to(modules::get_elector))
                            .route("/get_electores", web::get().to(modules::get_electores))
                            .route(
                                "/get_votos_emitir/{nacionalidad}/{cedula}",
                                web::get().to(modules::get_votos_emitir),
                            )
                            .route("/usuarios", web::get().to(modules::get_usuarios))
                            .route("/usuarios", web::post().to(modules::crear_usuario))
                            .route("/usuarios/{id}", web::put().to(modules::actualizar_usuario))
                            .route("/usuarios/{id}", web::delete().to(modules::eliminar_usuario))
                            .route(
                                "/usuarios/{id}/reactivar",
                                web::put().to(modules::reactivar_usuario),
                            )
                            .route(
                                "/usuarios/{id}/bloquear",
                                web::put().to(modules::bloquear_usuario),
                            )
                            .route(
                                "/usuarios/validar-carga-masiva",
                                web::post().to(modules::validar_carga_masiva),
                            )
                            .route(
                                "/usuarios/confirmar-carga-masiva",
                                web::post().to(modules::confirmar_carga_masiva),
                            )
                            .route(
                                "/usuarios/plantilla",
                                web::get().to(modules::descargar_plantilla),
                            )
                            .route(
                                "/usuarios/carga-masiva/{id}/excel",
                                web::get().to(modules::descargar_carga_masiva_excel),
                            )
                            .route(
                                "/get_usuario_by_ac/{nacionalidad}/{cedula}",
                                web::get().to(modules::get_usuario_by_ac),
                            )
                            .route("/roles", web::get().to(modules::get_roles))
                            .route("/logs", web::get().to(modules::logs::get_logs))
                            .route(
                                "/logs/resumen",
                                web::get().to(modules::logs::get_logs_resumen),
                            )
                            .route(
                                "/logs/carga-masiva-id/{id}",
                                web::get().to(modules::logs::get_carga_masiva_id_by_log),
                            )
                            .route("/parametros", web::get().to(modules::get_parametros))
                            .route("/parametros", web::post().to(modules::crear_parametro))
                            .route(
                                "/parametros/{nombre}",
                                web::get().to(modules::get_parametro_by_nombre),
                            )
                            .route(
                                "/parametros/{id}",
                                web::put().to(modules::actualizar_parametro),
                            )
                            .route(
                                "/parametros/{id}",
                                web::delete().to(modules::eliminar_parametro),
                            )
                            .route(
                                "/parametros/fecha-cierre",
                                web::get().to(modules::get_fecha_cierre),
                            )
                            .route(
                                "/security/dashboard",
                                web::get().to(modules::security::get_security_dashboard),
                            )
                            .route(
                                "/exportar/reporte",
                                web::post().to(modules::exportacion::registrar_exportacion),
                            ),
                    ),
            )
    })
    .bind(("127.0.0.1", 9000))?
    .run()
    .await
}