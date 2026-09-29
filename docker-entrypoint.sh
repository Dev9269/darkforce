#!/bin/sh
# Managed platforms (Railway, Render, Fly, Spaces) mount persistent volumes as
# root:root. The server itself must not run as root, so fix ownership here and
# then drop privileges before exec'ing the app.
set -e

APP_UID=65534
APP_GID=65534
DATA_DIR="${DATA_DIR:-/app/data}"

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    # Volumes reject chown on some backends; failure here is not fatal because
    # the app also works fully in-memory when the dir is not writable.
    chown -R "$APP_UID:$APP_GID" "$DATA_DIR" 2>/dev/null || true

    # Tor: the image ships the distro `tor` package, which is far smaller than
    # the vendored expert bundle. Start it before dropping privileges so the app
    # finds a live SOCKS listener on 127.0.0.1:9050 (external_running()).
    # Without Tor the collector still works, but .onion seeds are unreachable.
    if [ "${ENABLE_TOR:-1}" = "1" ] && command -v tor >/dev/null 2>&1; then
        TOR_DATA="$DATA_DIR/tor"
        mkdir -p "$TOR_DATA"
        chown -R "$APP_UID:$APP_GID" "$TOR_DATA" 2>/dev/null || true
        # Run as the app user so every file tor creates is already owned by it;
        # tor refuses to start as root with a non-root data directory anyway.
        gosu "$APP_UID:$APP_GID" tor \
            --DataDirectory "$TOR_DATA" \
            --SocksPort 9050 \
            --CookieAuthentication 0 \
            --Log 'notice stdout' >"$DATA_DIR/tor-container.log" 2>&1 &
        echo "[entrypoint] tor started (pid $!), waiting for SOCKS..."
    fi

    exec gosu "$APP_UID:$APP_GID" "$0" "$@"
fi

# Wait for SOCKS. A cold Tor bootstrap routinely takes 30-90s, so allow 150s:
# starting the first collection pass before the circuit is up just fails every
# .onion fetch and the results are cached as "unreachable" for the sweep window.
if [ "${ENABLE_TOR:-1}" = "1" ]; then
    i=0
    while [ $i -lt 150 ]; do
        if python -c "import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(('127.0.0.1',9050))==0 else 1)" 2>/dev/null; then
            echo "[entrypoint] tor SOCKS listening after ${i}s"
            break
        fi
        i=$((i + 1))
        sleep 1
    done
    if [ $i -ge 150 ]; then
        echo "[entrypoint] WARNING: tor SOCKS never opened; .onion seeds will be skipped"
        tail -n 20 "$DATA_DIR/tor-container.log" 2>/dev/null || true
    fi
fi

# demo (default): seeded corpus, no outbound crawling, ready immediately
# live:           pull real clearnet seeds and crawl them on startup
case "${DATA_MODE:-demo}" in
    live) ARGS="--live" ;;
    *)    ARGS="--demo" ;;
esac

# DAEMON_MODE=1 keeps a background collector running on top of the dashboard.
if [ -n "$DAEMON_MODE" ]; then
    ARGS="$ARGS --daemon --live"
fi

# exec so the app is PID 1's direct child: signals reach it, restarts are clean.
exec python run.py $ARGS
