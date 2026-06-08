FROM python:3.11-slim

# Playwright needs these system libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements-mcp.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-mcp.txt

# Install Playwright browser (chromium only — used for browser-based evidence)
RUN playwright install chromium --with-deps 2>/dev/null || true

COPY agent/ agent/
COPY frameworks/ frameworks/
COPY mcp_server/ mcp_server/

# MCP server listens on 8765 (SSE transport)
EXPOSE 8765

ENV MCP_PORT=8765
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "mcp_server.server"]
