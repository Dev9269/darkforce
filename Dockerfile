FROM python:3.12-slim

WORKDIR /app

# System deps: curl for the healthcheck; Tor is optional (clearnet-only works
# without it). Tor can be wired in on a host that provides it via TOR_EXTERNAL.
RUN apt-get update && apt-get install -y --no-install-recommends \
        tor \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root with a writable data dir (SQLite + generated secrets).
RUN mkdir -p /app/data && chown -R 65534:65534 /app/data
USER 65534

# Architecture of the entrypoint: the image is generic and always starts the
# server; the DATA_MODE env chooses what populates the dashboard on first boot.
#   demo (default): seeded corpus - instant data, no outbound crawling, perfect
#                   for review/video/oommf
#   live:           pulls real clearnet seeds and crawls them on startup
# Set DATA_MODE=live (or DAEMON_MODE=1) to change it on the host.
ENV DATA_MODE=demo
EXPOSE 8000
ENTRYPOINT ["sh", "-c", "python run.py --${DATA_MODE}${DAEMON_MODE:+ --daemon --live}"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
  CMD curl -f http://localhost:${PORT:-8000}/healthz || exit 1