# Stage 1: Build
FROM node:20-slim AS builder
WORKDIR /app

# Copy workspace root and package configs
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/server/package.json packages/server/

# Install all dependencies including root devDependencies (tsup, typescript)
RUN npm ci

# Copy source
COPY packages/core packages/core
COPY packages/server packages/server

# Build core first, then server
RUN cd packages/core && npx tsup
RUN cd packages/server && npx tsup

# Stage 2: Optional model pre-download
# Build with: docker build --build-arg PRELOAD_MODEL=true -t bulkhead .
FROM node:20-slim AS model-downloader
ARG PRELOAD_MODEL=false
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/core/package.json ./packages/core/
COPY --from=builder /app/packages/server/src/preload-model.ts ./preload-model.ts
ENV TRANSFORMERS_CACHE=/app/models
RUN mkdir -p /app/models
RUN if [ "$PRELOAD_MODEL" = "true" ]; then \
      npx tsx preload-model.ts; \
    fi

# Stage 3: Runtime
FROM node:20-slim AS runtime

# Create non-root user
RUN addgroup --system bulkhead && adduser --system --ingroup bulkhead bulkhead

WORKDIR /app

# Copy built artifacts and production dependencies
COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/core/package.json ./packages/core/
COPY --from=builder /app/packages/server/dist ./packages/server/dist
COPY --from=builder /app/packages/server/package.json ./packages/server/

# BERT model cache directory (pre-downloaded if PRELOAD_MODEL=true)
ENV TRANSFORMERS_CACHE=/app/models
COPY --from=model-downloader /app/models ./models
RUN chown -R bulkhead:bulkhead /app/models
VOLUME /app/models

# Security: run as non-root
USER bulkhead

EXPOSE 3000

# Default: HTTP REST server. Override for MCP stdio mode.
# Usage:
#   docker run bulkhead                                          → HTTP server on :3000
#   docker run -i bulkhead packages/server/dist/mcp/index.js     → MCP server on stdio
#   docker build --build-arg PRELOAD_MODEL=true -t bulkhead .    → Pre-download BERT model
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/healthz').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

ENTRYPOINT ["node"]
CMD ["packages/server/dist/main.js"]
