FROM python:3.12-slim

WORKDIR /app

# System deps: curl for the healthcheck; Tor is optional (clearnet-only works
# without it). Tor can be wired in on a host that provides it via TOR_EXTERNAL.
RUN apt-get update && apt-get install -y --no-install-recommends \
        tor \
        curl \
        gosu \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Managed hosts mount the volume as root:root, so the app must start as root to
# chown /app/data, then drop to the unprivileged user for the actual server.
# gosu does this without a second process left behind.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV DATA_MODE=demo
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD []