#!/bin/bash
set -e

case "$1" in
  deploy)
    echo "ðŸš€ Pulling latest code..."
    git pull origin master
    echo "ðŸ”¨ Building and starting containers..."
    docker compose up -d --build
    echo "âœ… Deployment complete"
    docker compose ps
    ;;
  logs)
    docker compose logs --tail=50 -f
    ;;
  status)
    docker compose ps
    echo ""
    echo "ðŸ“Š Disk usage:"
    docker system df
    ;;
  rebuild-frontend)
    echo "ðŸ”¨ Rebuilding frontend (no-cache)..."
    docker compose build --no-cache frontend
    docker compose up -d frontend
    echo "âœ… Frontend rebuilt"
    ;;
  rebuild-backend)
    echo "ðŸ”¨ Rebuilding backend (no-cache)..."
    docker compose build --no-cache backend
    docker compose up -d backend
    echo "âœ… Backend rebuilt"
    ;;
  db-shell)
    source .env
    docker compose exec db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
    ;;
  *)
    echo "Usage: ./deploy.sh {deploy|logs|status|rebuild-frontend|rebuild-backend|db-shell}"
    exit 1
    ;;
esac
