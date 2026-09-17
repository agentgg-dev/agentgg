# Live-validation sandbox: Playwright + Chromium + @playwright/mcp SSE server.
# Build from the repo root (tag must match DEFAULT_SANDBOX_IMAGE in sandbox.ts):
#   docker build -f packages/cli/src/validation/sandbox.Dockerfile -t agentgg/live-sandbox:pw1.56.0-mcp0.0.41 .
#
# Verified 2026-09-16 against the published packages:
#   @playwright/mcp@0.0.41 CLI flags: --port --host --headless --isolated --no-sandbox --save-trace --save-video --output-dir
#   endpoints on --port: /mcp (streamable HTTP, primary) and /sse (legacy SSE, used for readiness/connect)
#   0.0.41 depends on playwright 1.56.0-alpha; the v1.56.0 base image supplies the OS deps.
FROM mcr.microsoft.com/playwright:v1.56.0-noble

WORKDIR /srv

# Install the MCP server and the exact playwright it targets, then fetch the matching
# Chromium build (the base image ships stable 1.56.0 browsers; the alpha may differ).
RUN npm install -g @playwright/mcp@0.0.41 playwright@1.56.0-alpha-2025-10-01 \
  && playwright install chromium

# Trace/video/session artifacts land here; the host copies them out.
RUN mkdir -p /out

EXPOSE 8931

# --no-sandbox: Chromium runs as root in the container.
# --isolated: fresh in-memory profile per run.
# --save-trace/--save-video: Playwright trace (includes network activity) + video into /out.
CMD ["mcp-server-playwright", \
  "--port", "8931", \
  "--host", "0.0.0.0", \
  "--headless", \
  "--isolated", \
  "--no-sandbox", \
  "--save-trace", \
  "--save-video", "800x600", \
  "--output-dir", "/out"]
