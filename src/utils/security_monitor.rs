// src/utils/security_monitor.rs
use chrono::{DateTime, Utc, Duration};
use log::{warn, error};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// ✅ Tipos de eventos de seguridad
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityEvent {
    HoneypotTriggered { ip: String, cedula: Option<i32> },
    RateLimitExceeded { ip: String, attempts: u32 },
    InvalidCaptcha { ip: String, cedula: Option<i32> },
    BruteForceDetected { target: String, attempts: u32, window_minutes: u32 },
    SuspiciousUserAgent { ip: String, user_agent: String },
    UnauthorizedAccess { ip: String, endpoint: String, user_id: Option<i32> },
}

// ✅ Configuración de alertas
#[derive(Clone)]
pub struct AlertConfig {
    pub rate_limit_threshold: u32,
    pub rate_limit_window_minutes: u32,
    pub log_file: String,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            rate_limit_threshold: 10,
            rate_limit_window_minutes: 5,
            log_file: "logs/security_alerts.log".to_string(),
        }
    }
}

// ✅ Tracker para monitoreo por IP
#[derive(Debug)]
pub struct IpTracker {
    pub events: Vec<(DateTime<Utc>, SecurityEvent)>,
    pub alert_sent: bool,
}

// ✅ Monitor de seguridad (thread-safe)
pub struct SecurityMonitor {
    config: AlertConfig,
    ip_trackers: Arc<Mutex<HashMap<String, IpTracker>>>,
}

impl SecurityMonitor {
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            ip_trackers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ✅ Registrar evento de seguridad
    pub fn record_event(&self, ip: &str, event: SecurityEvent) {
        let now = Utc::now();
        
        // 1. Loguear inmediatamente
        self.log_event(ip, &event, now);
        
        // 2. Actualizar tracker por IP
        self.update_ip_tracker(ip, now, event.clone());
        
        // 3. Evaluar si enviar alerta crítica
        self.evaluate_alert(ip);
    }

    fn log_event(&self, ip: &str, event: &SecurityEvent, timestamp: DateTime<Utc>) {
        let event_str = match event {
            SecurityEvent::HoneypotTriggered { cedula, .. } => 
                format!("HONEYPOT - IP: {} - Cédula: {:?}", ip, cedula),
            SecurityEvent::RateLimitExceeded { attempts, .. } => 
                format!("RATE LIMIT - IP: {} - Intentos: {}", ip, attempts),
            SecurityEvent::InvalidCaptcha { cedula, .. } => 
                format!("CAPTCHA INVÁLIDO - IP: {} - Cédula: {:?}", ip, cedula),
            SecurityEvent::BruteForceDetected { target, attempts, .. } => 
                format!("FUERZA BRUTA - Target: {} - Intentos: {}", target, attempts),
            SecurityEvent::SuspiciousUserAgent { user_agent, .. } => 
                format!("USER AGENTE SOSPECHOSO - IP: {} - UA: {}", ip, user_agent),
            SecurityEvent::UnauthorizedAccess { endpoint, .. } => 
                format!("ACCESO NO AUTORIZADO - IP: {} - Endpoint: {}", ip, endpoint),
        };
        
        // Log estructurado para análisis posterior
        warn!(
            target: "security",
            "ALERTA_SEGURIDAD | timestamp={} | ip={} | event={}",
            timestamp.timestamp(),
            ip,
            event_str
        );
    }

    fn update_ip_tracker(&self, ip: &str, now: DateTime<Utc>, event: SecurityEvent) {
        let mut trackers = self.ip_trackers.lock().unwrap();
        
        let tracker = trackers.entry(ip.to_string()).or_insert(IpTracker {
            events: Vec::new(),
            alert_sent: false,
        });
        
        // Mantener solo eventos de la última hora
        let cutoff = now - Duration::hours(1);
        tracker.events.retain(|(ts, _)| *ts > cutoff);
        
        tracker.events.push((now, event));
    }

    fn evaluate_alert(&self, ip: &str) {
        let trackers = self.ip_trackers.lock().unwrap();
        
        if let Some(tracker) = trackers.get(ip) {
            if tracker.alert_sent {
                return; // Ya se envió alerta para esta IP
            }
            
            let window = Duration::minutes(self.config.rate_limit_window_minutes as i64);
            let now = Utc::now();
            
            // Contar eventos críticos en la ventana
            let critical_count = tracker.events.iter()
                .filter(|(ts, _)| now - *ts < window)
                .filter(|(_, event)| matches!(
                    event,
                    SecurityEvent::HoneypotTriggered { .. } |
                    SecurityEvent::RateLimitExceeded { .. } |
                    SecurityEvent::BruteForceDetected { .. }
                ))
                .count();
            
            if critical_count >= self.config.rate_limit_threshold as usize {
                drop(trackers); // Liberar lock antes de alertar
                self.send_critical_alert(ip, critical_count);
                
                // Marcar como alertada
                if let Some(tracker) = self.ip_trackers.lock().unwrap().get_mut(ip) {
                    tracker.alert_sent = true;
                }
            }
        }
    }

    fn send_critical_alert(&self, ip: &str, event_count: usize) {
        error!(
            target: "security_alert",
            "🚨 ALERTA CRÍTICA: IP {} - {} eventos sospechosos en {} minutos",
            ip,
            event_count,
            self.config.rate_limit_window_minutes
        );
    }

    // ✅ Obtener estadísticas para dashboard (opcional)
   pub fn get_stats(&self) -> HashMap<String, usize> {
    let trackers = self.ip_trackers.lock().unwrap();
    let mut stats: HashMap<String, usize> = HashMap::new();  // ← Tipo explícito
    
    stats.insert("total_ips_monitored".to_string(), trackers.len());  // ← .to_string()
    
    let critical_events: usize = trackers.values()
        .flat_map(|t| &t.events)
        .filter(|(_, e)| matches!(
            e,
            SecurityEvent::HoneypotTriggered { .. } |
            SecurityEvent::BruteForceDetected { .. }
        ))
        .count();
    
    stats.insert("critical_events_last_hour".to_string(), critical_events);  // ← .to_string()
    
    stats
}
}

// ✅ Instancia global (lazy static)
use once_cell::sync::Lazy;

pub static SECURITY_MONITOR: Lazy<SecurityMonitor> = 
    Lazy::new(|| SecurityMonitor::new(AlertConfig::default()));

// ✅ Helpers para uso fácil en endpoints
pub fn alert_honeypot(ip: &str, cedula: Option<i32>) {
    SECURITY_MONITOR.record_event(ip, SecurityEvent::HoneypotTriggered { 
        ip: ip.to_string(), cedula 
    });
}

pub fn alert_rate_limit(ip: &str, attempts: u32) {
    SECURITY_MONITOR.record_event(ip, SecurityEvent::RateLimitExceeded { 
        ip: ip.to_string(), attempts 
    });
}

pub fn alert_invalid_captcha(ip: &str, cedula: Option<i32>) {
    SECURITY_MONITOR.record_event(ip, SecurityEvent::InvalidCaptcha { 
        ip: ip.to_string(), cedula 
    });
}

pub fn alert_brute_force(target: &str, attempts: u32) {
    SECURITY_MONITOR.record_event("system", SecurityEvent::BruteForceDetected { 
        target: target.to_string(), attempts, window_minutes: 15 
    });
}