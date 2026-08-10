#!/usr/bin/env bash
# Start local Keycloak via deploy/docker-compose.yml and run the compose
# discovery test. Skips cleanly when Docker is unavailable.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:${PATH:-}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found — skipping Keycloak compose test"
  echo "Unit soft-fail / Fake IdP tests: go test -count=1 ./..."
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon not reachable — skipping Keycloak compose test"
  echo "Unit soft-fail / Fake IdP tests: go test -count=1 ./..."
  exit 0
fi

export KEYCLOAK_HOST_PORT="${KEYCLOAK_HOST_PORT:-18080}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-auth-oidc-keycloak}"

cleanup() {
  docker compose -f deploy/docker-compose.yml down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> docker compose up (Keycloak on 127.0.0.1:${KEYCLOAK_HOST_PORT})"
if ! docker compose -f deploy/docker-compose.yml up -d --wait --wait-timeout 120; then
  echo "compose --wait failed; falling back to up -d + poll"
  docker compose -f deploy/docker-compose.yml up -d
fi

echo "==> go test Keycloak discovery"
go test -count=1 -timeout 5m ./internal/oidc/ -run TestKeycloakComposeDiscovery -v
