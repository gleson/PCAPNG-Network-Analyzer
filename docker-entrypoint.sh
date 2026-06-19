#!/bin/bash
set -e

echo "Aguardando PostgreSQL..."

# Aguardar PostgreSQL estar pronto (backup do healthcheck)
until python -c "
import psycopg2
import os
try:
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    conn.close()
    print('PostgreSQL disponivel')
except Exception as e:
    print(f'Aguardando... {e}')
    exit(1)
" 2>/dev/null; do
    sleep 1
done

mkdir -p data/uploads

echo "Iniciando PCAP Network Analyzer (Gunicorn)..."

# Producao roda sob Gunicorn — NUNCA o servidor de desenvolvimento do Flask
# (single-process, sem hardening, e historicamente usado com debug=True).
#
# workers=1 e proposital: a aplicacao compartilha o progresso da analise em
# memoria de processo (routes/common.py::analysis_status / analysis_lock).
# Varios workers fragmentariam esse estado e quebrariam /api/status e o SSE.
# A concorrencia vem das threads (gthread), equivalente ao antigo
# app.run(threaded=True). gthread tambem lida bem com a conexao SSE longa
# de /api/status/stream sem disparar o --timeout.
exec gunicorn \
    --bind 0.0.0.0:5000 \
    --worker-class gthread \
    --workers "${GUNICORN_WORKERS:-1}" \
    --threads "${GUNICORN_THREADS:-8}" \
    --timeout "${GUNICORN_TIMEOUT:-120}" \
    --graceful-timeout 30 \
    --access-logfile - \
    --error-logfile - \
    app:app
