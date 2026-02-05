use actix_web::{web, HttpResponse, Error};
use oracle::{Connection, Row, RowValue};
use std::env;

#[derive(serde::Serialize)]
struct MovimientoRE {
    CIERRE: i32,
    NOMBRE_CORTO: Option<String>,
    ID_LOTE: i32,
    DESCRIPCION_MOVIMIENTO: String,
    DESCRIPCION_STATUS: String,
    FECHA_PROCESO_MOV: String,
}

impl RowValue for MovimientoRE {
    fn get(row: &Row) -> std::result::Result<MovimientoRE, oracle::Error> {
        Ok(MovimientoRE {
            CIERRE: row.get("CIERRE")?,
            NOMBRE_CORTO: row.get("NOMBRE_CORTO")?,
            ID_LOTE: row.get("ID_LOTE")?,
            DESCRIPCION_MOVIMIENTO: row.get("DESCRIPCION_MOVIMIENTO")?,
            DESCRIPCION_STATUS: row.get("DESCRIPCION_STATUS")?,
            FECHA_PROCESO_MOV: row.get("FECHA_PROCESO_MOV")?,
        })
    }
}

pub async fn get_movimientos_re(
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, Error> {
    // ✅ CORRECTO: Usar into_inner() para extraer los valores
    let (nacionalidad, cedula) = path.into_inner();
    let nacionalidad = nacionalidad.to_uppercase();
    
    let username = env::var("ORACLE_USER").unwrap();
    let password = env::var("ORACLE_PASS").unwrap();
    let oracle_ip = env::var("ORACLE_IP").unwrap();
    let oracle_port = env::var("ORACLE_PORT").unwrap();
    let oracle_db = env::var("ORACLE_DB").unwrap();
    let connect_string = format!("//{oracle_ip}:{oracle_port}/{oracle_db}");

    let conn = Connection::connect(username, password, connect_string)
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error conectando a Oracle: {}", e)))?;

    let sql = "SELECT
                t.CIERRE, c.NOMBRE_CORTO, t.ID_LOTE, tm.DESCRIPCION DESCRIPCION_MOVIMIENTO,
                spm.descripcion DESCRIPCION_STATUS, t.FECHA_PROCESO_MOV
                from re.movimiento t
                left join re.cierre c
                on t.cierre=c.codigo
                left join re.tipo_movimiento tm
                on t.tipo_movimiento=tm.tipo_movimiento
                left join re.status_proceso_mov spm
                on t.status_proceso_mov=spm.codigo
                where t.nacionalidad= :nacionalidad
                And T.Cedula_Number= :cedula
                order by cierre desc";

    let rows = conn.query_as::<MovimientoRE>(sql, &[&nacionalidad, &cedula])
        .map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error ejecutando query: {}", e)))?;

    let mut re_array: Vec<MovimientoRE> = Vec::new();

    for row_result in rows {
        let mov = row_result.map_err(|e| actix_web::error::ErrorInternalServerError(format!("Error procesando fila: {}", e)))?;
        re_array.push(mov);
    }

    Ok(HttpResponse::Ok().json(&re_array))
}
