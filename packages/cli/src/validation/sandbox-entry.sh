#!/bin/sh
# Starts the control server when a token is set (attached mode), then the MCP server.
set -e
LOG=/tmp/mcp.log
if [ -n "$SANDBOX_CONTROL_TOKEN" ]; then
  node /srv/sandbox-control.mjs "$LOG" &
fi
set -- mcp-server-playwright --port 8931 --host 0.0.0.0 --headless --isolated --no-sandbox \
  --browser chromium --init-script /srv/url-banner.js --save-trace --save-video 800x600 --output-dir /out
if [ -n "$ALLOWED_ORIGINS" ]; then
  set -- "$@" --allowed-origins "$ALLOWED_ORIGINS"
fi
exec "$@" 2>&1 | tee "$LOG"
