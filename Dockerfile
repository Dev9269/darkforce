FROM python:3.12-slim

WORKDIR /app

# System deps: Tor (for .onion crawling through the sidecar is optional,
# but keeping the build minimal; the app also works clearnet-only).
RUN apt-get update && apt-get install -y --no-install-recommends \
        tor \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root
RUN mkdir -p /app/data && chown -R 65534:65534 /app/data
USER 65534

EXPOSE 8000
CMD ["python", "run.py"]