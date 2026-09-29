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
    exec gosu "$APP_UID:$APP_GID" "$0" "$@"
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
