#!/usr/bin/env bash
# ==============================================================================
# Script to launch authorized reference target: OWASP Juice Shop
# ==============================================================================

set -euo pipefail

CONTAINER_NAME="authscope-juice-shop"
PORT="3000"

echo "[*] Checking if OWASP Juice Shop container is already running..."

if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "[+] ${CONTAINER_NAME} is already running on port ${PORT}."
    echo "[+] Accessible at: http://localhost:${PORT}"
    exit 0
fi

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "[*] Starting existing container: ${CONTAINER_NAME}..."
    docker start "${CONTAINER_NAME}"
else
    echo "[*] Pulling and launching new container: ${CONTAINER_NAME} on port ${PORT}..."
    docker run -d --name "${CONTAINER_NAME}" -p "${PORT}:${PORT}" bkimminich/juice-shop
fi

echo "[+] OWASP Juice Shop initialized successfully!"
echo "[+] Target URL: http://localhost:${PORT}"

