#!/bin/bash
# Script to run the SpamNoMore API server

# Default values
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
RELOAD="${RELOAD:-false}"

echo "Starting SpamNoMore API..."
echo "Host: $HOST"
echo "Port: $PORT"
echo ""

if [ "$RELOAD" = "true" ]; then
    echo "Running in development mode with auto-reload..."
    uvicorn app.main:app --host "$HOST" --port "$PORT" --reload
else
    echo "Running in production mode..."
    uvicorn app.main:app --host "$HOST" --port "$PORT"
fi