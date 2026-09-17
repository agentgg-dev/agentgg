# Live-validation sandbox: Playwright + Chromium + @playwright/mcp SSE server.
# Build with this file's own directory as the context (it COPYs url-banner.js):
#   docker build -f packages/cli/src/validation/sandbox.Dockerfile -t agentgg/live-sandbox:pw1.56.0-mcp0.0.41-2 packages/cli/src/validation
#
# @playwright/mcp 0.0.41 pinned: it depends on playwright 1.56.0-alpha, so the
# image installs that exact playwright and its matching chromium on top of the
# v1.56.0 base (which supplies the OS deps). Serves /mcp (streamable HTTP) and
# /sse (legacy SSE, used for readiness/connect) on --port.
FROM mcr.microsoft.com/playwright:v1.56.0-noble

WORKDIR /srv

# Install the MCP server and the exact playwright it targets, then fetch the matching
# Chromium build (the base image ships stable 1.56.0 browsers; the alpha may differ).
RUN npm install -g @playwright/mcp@0.0.41 playwright@1.56.0-alpha-2025-10-01 \
  && playwright install chromium

# Trace/video/session artifacts land here; the host copies them out.
RUN mkdir -p /out

# Fixed URL banner overlay, so the recorded video shows the address of each step.
COPY url-banner.js /srv/url-banner.js

EXPOSE 8931

# --browser chromium: the MCP server defaults to the Google Chrome channel, which
# this image does not ship; without this the first navigation fails and the agent
# has to repair it with a 435MB browser_install.
# --init-script: fixed URL banner, so the video shows the address of each step.
# --no-sandbox: Chromium runs as root in the container.
# --isolated: fresh in-memory profile per run.
# --save-trace/--save-video: Playwright trace (includes network activity) + video into /out.
CMD ["mcp-server-playwright", \
  "--port", "8931", \
  "--host", "0.0.0.0", \
  "--headless", \
  "--isolated", \
  "--no-sandbox", \
  "--browser", "chromium", \
  "--init-script", "/srv/url-banner.js", \
  "--save-trace", \
  "--save-video", "800x600", \
  "--output-dir", "/out"]
