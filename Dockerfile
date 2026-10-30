# Runs the free, read-only MCP server over stdio (used by Glama and any MCP client that starts servers from a Docker image).
# Build: docker build -t devx-mcp .   Run: docker run -i --rm devx-mcp
FROM node:22-alpine
WORKDIR /app
COPY cli/package*.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY cli/ ./
ENV NODE_ENV=production
USER node
ENTRYPOINT ["node", "bin/cli.js", "mcp"]
