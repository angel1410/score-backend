#![allow(non_snake_case)]

use dotenvy::dotenv;
use modules::*;
use ntex::http::{self};
use ntex::web::{App, HttpServer, get, post, scope};
use ntex_cors::Cors;
use sqlx::postgres::PgPool;
use std::env;

// Definimos el AppState aquí o impórtalo si lo prefieres mantener separado,
// pero asegúrate de actualizar la definición del struct.
mod structs {
  use sqlx::postgres::PgPool;
  pub struct AppState {
    pub pool_pg: PgPool,
    pub jwt_secret: String,
  }
}

#[ntex::main]
async fn main() -> std::io::Result<()> {
  dotenv().ok();
  let ALLOWED_ORIGIN = env::var("ALLOWED_ORIGIN").expect("Variable ALLOWED_ORIGIN faltante");
  let url_pg = env::var("PG_URL").expect("Variable PG_URL faltante");
  let jwt_secret = env::var("JWT_SECRET").expect("Variable JWT_SECRET faltante"); // <--- CARGAMOS EL SECRETO

  let pool_pg = PgPool::connect(&url_pg).await.expect("Error conectando a BD");

  HttpServer::new(move || {
    App::new()
      .wrap(
        Cors::new()
          .allowed_origin(ALLOWED_ORIGIN.as_str())
          .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
          .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT, http::header::CONTENT_TYPE])
          .max_age(3600)
          .finish(),
      )
      // Pasamos el secreto al estado
      .state(structs::AppState {
        pool_pg: pool_pg.clone(),
        jwt_secret: jwt_secret.clone(),
      })
      .service(
        scope("/api")
          .route("/login", post().to(get_login))
          .route("/get-movimientos-re/{nacionalidad}/{cedula}", get().to(get_movimientos_re)),
      )
  })
  .bind(("127.0.0.1", 9000))?
  .run()
  .await
}

mod modules {
  // WS de Consultas
  mod login;
  mod re;
  pub use login::get_login;
  pub use re::get_movimientos_re;
}
