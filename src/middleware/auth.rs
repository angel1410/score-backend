// src/middleware/auth.rs
#![allow(dead_code)]
use actix_web::{
    body::{EitherBody, MessageBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
    web, Error, HttpMessage, HttpRequest, HttpResponse,
};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::structs::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareInner<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareInner { service })
    }
}

pub struct AuthMiddlewareInner<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareInner<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let app_state = req.app_data::<web::Data<AppState>>().cloned();

        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);

        let validation_result = match (app_state, auth_header) {
            (Some(state), Some(auth_value)) => {
                let token = auth_value.strip_prefix("Bearer ").unwrap_or("").trim();

                if token.is_empty() {
                    Err("Token faltante")
                } else {
                    match decode::<Claims>(
                        token,
                        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
                        &Validation::default(),
                    ) {
                        Ok(token_data) => {
                            req.extensions_mut().insert(token_data.claims);
                            Ok(())
                        }
                        Err(_) => Err("Token inválido o expirado"),
                    }
                }
            }
            (None, _) => Err("AppState no disponible"),
            (_, None) => Err("Header Authorization faltante"),
        };

        if let Err(message) = validation_result {
            let response = HttpResponse::Unauthorized().json(serde_json::json!({
                "error": message
            }));
            let res = req.into_response(response).map_into_right_body();
            return Box::pin(async { Ok(res) });
        }

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?.map_into_left_body();
            Ok(res)
        })
    }
}

pub fn get_claims(req: &HttpRequest) -> Result<Claims, HttpResponse> {
    req.extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Claims no disponibles"
            }))
        })
}

pub fn get_current_user_id(req: &HttpRequest) -> Result<i32, HttpResponse> {
    let claims = get_claims(req)?;
    claims.sub.parse::<i32>().map_err(|_| {
        HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "ID de usuario inválido en token"
        }))
    })
}

pub fn get_current_role(req: &HttpRequest) -> Result<String, HttpResponse> {
    let claims = get_claims(req)?;
    Ok(normalize_role(&claims.role))
}

fn normalize_role(role: &str) -> String {
    match role.trim().to_uppercase().as_str() {
        "1" | "ADMINISTRADOR" | "ADMIN" => "ADMINISTRADOR".to_string(),
        "2" | "DIRECTOR" | "CONSULTOR" => "DIRECTOR".to_string(),
        "3" | "OPERADOR" => "OPERADOR".to_string(),
        "4" | "SISTEMAS" | "SISTEMA" => "SISTEMAS".to_string(),
        other => other.to_string(),
    }
}

pub fn require_any_role(req: &HttpRequest, allowed: &[&str]) -> Result<(), HttpResponse> {
    let role = get_current_role(req)?;

    let is_allowed = allowed
        .iter()
        .any(|allowed_role| normalize_role(allowed_role) == role);

    if is_allowed {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "No tiene permisos para realizar esta acción",
            "role": role
        })))
    }
}

pub fn require_admin_or_sistemas(req: &HttpRequest) -> Result<(), HttpResponse> {
    require_any_role(req, &["1", "4", "ADMINISTRADOR", "SISTEMAS"])
}

pub fn require_consulta_completa(req: &HttpRequest) -> Result<(), HttpResponse> {
    require_any_role(req, &["1", "2", "4", "ADMINISTRADOR", "DIRECTOR", "CONSULTOR", "SISTEMAS"])
}

pub fn require_consulta_basica(req: &HttpRequest) -> Result<(), HttpResponse> {
    require_any_role(
        req,
        &[
            "1",
            "2",
            "3",
            "4",
            "ADMINISTRADOR",
            "DIRECTOR",
            "CONSULTOR",
            "SISTEMAS",
        ],
    )
}

pub fn is_operador(req: &HttpRequest) -> bool {
    matches!(get_current_role(req), Ok(role) if role == "OPERADOR")
}

pub fn is_director(req: &HttpRequest) -> bool {
    matches!(get_current_role(req), Ok(role) if role == "DIRECTOR")
}

pub fn is_consultor(req: &HttpRequest) -> bool {
    is_director(req)
}

pub fn is_administrador(req: &HttpRequest) -> bool {
    matches!(get_current_role(req), Ok(role) if role == "ADMINISTRADOR")
}

pub fn is_sistemas(req: &HttpRequest) -> bool {
    matches!(get_current_role(req), Ok(role) if role == "SISTEMAS")
}

pub fn is_admin_or_sistemas(req: &HttpRequest) -> bool {
    matches!(get_current_role(req), Ok(role) if role == "ADMINISTRADOR" || role == "SISTEMAS")
}

pub fn is_consulta_completa(req: &HttpRequest) -> bool {
    matches!(
        get_current_role(req),
        Ok(role) if role == "ADMINISTRADOR" || role == "DIRECTOR" || role == "SISTEMAS"
    )
}