#!/bin/bash
echo "🧹 Limpiando variables Oracle de otros proyectos..."
unset ORACLE_USER
unset ORACLE_PASS
unset ORACLE_IP
unset ORACLE_PORT
unset ORACLE_DB

echo "🚀 Iniciando SCORE Backend..."
cd /home/angel/Documentos/score-backend
cargo run
