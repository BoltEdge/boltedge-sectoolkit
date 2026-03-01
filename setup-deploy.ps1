# SecToolkit Deployment Files Setup Script
# Run this from your project root: C:\Users\iradu\OneDrive\Desktop\Figma\SecToolKit - BoltEdge\
# Usage: .\setup-deploy.ps1

$ErrorActionPreference = "Stop"

Write-Host "Setting up SecToolkit deployment files..." -ForegroundColor Cyan

# ── .gitignore (project root) ──
@'
# Dependencies
node_modules/
frontend/node_modules/
backend/__pycache__/
backend/app/__pycache__/
backend/app/**/__pycache__/
*.pyc

# Environment
.env
backend/.env

# Next.js
frontend/.next/
frontend/out/

# Data files (large/licensed)
backend/app/data/*.mmdb
backend/app/data/oui.txt

# OS
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/

# Docker
*.log
'@ | Set-Content -Path ".gitignore" -Encoding UTF8
Write-Host "  Created .gitignore" -ForegroundColor Green

# ── .env.example (project root) ──
@'
# Database
POSTGRES_DB=sectoolkit
POSTGRES_USER=sectoolkit
POSTGRES_PASSWORD=           # Generate: openssl rand -hex 16

# Flask
SECRET_KEY=                  # Generate: python3 -c "import secrets; print(secrets.token_hex(32))"
FLASK_ENV=production
CORS_ORIGINS=https://sectoolkit.boltedge.co

# Frontend (baked into build)
NEXT_PUBLIC_API_URL=https://sectoolkit.boltedge.co/api

# Optional external API keys (enrichment only)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
GREYNOISE_API_KEY=
'@ | Set-Content -Path ".env.example" -Encoding UTF8
Write-Host "  Created .env.example" -ForegroundColor Green

# ── docker-compose.yml (project root) ──
@'
version: '3.8'

services:
  db:
    image: postgres:16-alpine
    container_name: sectoolkit-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - sectoolkit_postgres_data:/var/lib/postgresql/data
    networks:
      - internal
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U ${POSTGRES_USER}']
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build: ./backend
    container_name: sectoolkit-backend
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}
      - CORS_ORIGINS=https://sectoolkit.boltedge.co
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY:-}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY:-}
      - SHODAN_API_KEY=${SHODAN_API_KEY:-}
      - GREYNOISE_API_KEY=${GREYNOISE_API_KEY:-}
    volumes:
      - ./backend/app/data:/app/app/data
    networks:
      - internal
      - boltedge-network
    expose:
      - '5003'

  frontend:
    build:
      context: ./frontend
      args:
        NEXT_PUBLIC_API_URL: https://sectoolkit.boltedge.co/api
    container_name: sectoolkit-frontend
    restart: unless-stopped
    depends_on:
      - backend
    networks:
      - boltedge-network
    expose:
      - '3002'

volumes:
  sectoolkit_postgres_data:

networks:
  internal:
    driver: bridge
  boltedge-network:
    external: true
'@ | Set-Content -Path "docker-compose.yml" -Encoding UTF8
Write-Host "  Created docker-compose.yml" -ForegroundColor Green

# ── deploy.sh (project root) ──
@'
#!/bin/bash
set -e

case "$1" in
  deploy)
    echo "🚀 Pulling latest code..."
    git pull origin master
    echo "🔨 Building and starting containers..."
    docker compose up -d --build
    echo "✅ Deployment complete"
    docker compose ps
    ;;
  logs)
    docker compose logs --tail=50 -f
    ;;
  status)
    docker compose ps
    echo ""
    echo "📊 Disk usage:"
    docker system df
    ;;
  rebuild-frontend)
    echo "🔨 Rebuilding frontend (no-cache)..."
    docker compose build --no-cache frontend
    docker compose up -d frontend
    echo "✅ Frontend rebuilt"
    ;;
  rebuild-backend)
    echo "🔨 Rebuilding backend (no-cache)..."
    docker compose build --no-cache backend
    docker compose up -d backend
    echo "✅ Backend rebuilt"
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
'@ | Set-Content -Path "deploy.sh" -Encoding UTF8
Write-Host "  Created deploy.sh" -ForegroundColor Green

# ── backend/Dockerfile ──
@'
FROM python:3.12-slim

WORKDIR /app

# System dependencies for network tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev iputils-ping traceroute whois dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5003
CMD ["gunicorn", "--bind", "0.0.0.0:5003", "--workers", "3", "--timeout", "120", "run:app"]
'@ | Set-Content -Path "backend\Dockerfile" -Encoding UTF8
Write-Host "  Created backend/Dockerfile" -ForegroundColor Green

# ── backend/.dockerignore ──
@'
__pycache__
*.pyc
.env
.git
.gitignore
*.md
'@ | Set-Content -Path "backend\.dockerignore" -Encoding UTF8
Write-Host "  Created backend/.dockerignore" -ForegroundColor Green

# ── frontend/Dockerfile ──
@'
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

EXPOSE 3002
CMD ["node", "server.js"]
'@ | Set-Content -Path "frontend\Dockerfile" -Encoding UTF8
Write-Host "  Created frontend/Dockerfile" -ForegroundColor Green

# ── frontend/.dockerignore ──
@'
node_modules
.next
.git
.gitignore
*.md
'@ | Set-Content -Path "frontend\.dockerignore" -Encoding UTF8
Write-Host "  Created frontend/.dockerignore" -ForegroundColor Green

# ── Fix long paths and push to GitHub ──
Write-Host "`nConfiguring Git..." -ForegroundColor Cyan
git config core.longpaths true
git add .
git commit -m "Add deployment config - Docker, Nginx, deploy script"
git push -u origin master

Write-Host "`n✅ All deployment files created and pushed to GitHub!" -ForegroundColor Green