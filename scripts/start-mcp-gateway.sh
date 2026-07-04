#!/bin/bash
set -e
export API_URL=http://localhost:3000
export API_KEY=$(grep ^MCP_API_KEY= /home/ubuntu/anki-cloud/.env | cut -d= -f2-)
exec /usr/bin/npx -y supergateway \
  --stdio "/home/ubuntu/.bun/bin/bun run /home/ubuntu/anki-cloud/mcp/src/index.ts" \
  --outputTransport streamableHttp \
  --port 3001 \
  --cors \
  --healthEndpoint /healthz