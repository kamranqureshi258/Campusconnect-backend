#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8000}"
echo "Starting CampusConnect backend on port ${PORT}"

exec gunicorn -k uvicorn.workers.UvicornWorker main:app --bind "0.0.0.0:${PORT}" --timeout 120

