# Stage 1: Build
FROM node:20-slim AS builder
WORKDIR /app

# Copy workspace root and package configs
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/server/package.json packages/server/

# Install dependencies (workspace-aware)
RUN npm ci --workspace=packages/core --workspace=packages/server

# Copy source
COPY packages/core packages/core
COPY packages/server packages/server

# Build core first, then server
RUN npx tsup --config packages/core/tsup.config.ts --outDir packages/core/dist
RUN npx tsup --config packages/server/tsup.config.ts --outDir packages/server/dist

# Stage 2: Runtime
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

# BERT model cache directory
ENV TRANSFORMERS_CACHE=/app/models
RUN mkdir -p /app/models && chown bulkhead:bulkhead /app/models
VOLUME /app/models

# Security: run as non-root
USER bulkhead

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/healthz').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node", "packages/server/dist/main.js"]
