# --- Stage 1: build the frontend bundle with Vite ---
FROM node:20-alpine AS frontend

WORKDIR /build

# Install npm deps with a cached layer.
COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

# Copy only what Vite needs and build the static bundle.
COPY vite.config.js ./
COPY frontend ./frontend
RUN npm run build


# --- Stage 2: runtime image ---
FROM python:3.11-slim

# Dependencias do sistema para Scapy, python-magic e matplotlib
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libmagic1 \
    tcpdump \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user. The app only reads PCAPs offline (no live capture),
# so it needs no extra Linux capabilities — running as root would merely hand
# a compromised analysis worker (Scapy parses untrusted input) full control
# of the container.
RUN useradd --create-home --uid 1000 appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Drop the built JS/CSS bundle (and its manifest) into static/dist/ where
# routes/vite.py looks for it.
COPY --from=frontend /build/static/dist ./static/dist

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Create writable runtime dirs, then hand the whole tree to the non-root user.
# The app_data volume is seeded from this image's /app/data, so chowning here
# means the seeded volume also lands appuser-owned.
RUN mkdir -p data/uploads data/artifacts \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

ENTRYPOINT ["/docker-entrypoint.sh"]
