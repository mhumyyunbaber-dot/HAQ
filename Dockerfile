# Pin these supported major tags to reviewed image digests before production rollout.
FROM node:24-bookworm-slim AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY --chown=node:node package.json package-lock.json ./
COPY --chown=node:node packages/http/internal.cjs ./packages/http/internal.cjs
COPY --chown=node:node scripts/healthcheck.cjs ./scripts/healthcheck.cjs
USER node

FROM runtime AS gateway
COPY --chown=node:node packages/http/edge.cjs ./packages/http/edge.cjs
COPY --chown=node:node services/gateway ./services/gateway
ENV SERVICE_NAME=gateway PORT=3000
CMD ["node","services/gateway/server.cjs"]

FROM runtime AS web
COPY --chown=node:node services/web/server.cjs ./services/web/server.cjs
COPY --chown=node:node index.html app.js auth-ui.js style.css ./services/web/assets/
ENV SERVICE_NAME=web PORT=3101 WEB_ASSET_DIR=/app/services/web/assets
CMD ["node","services/web/server.cjs"]

FROM runtime AS identity
COPY --chown=node:node auth.cjs ./auth.cjs
COPY --chown=node:node packages/storage ./packages/storage
COPY --chown=node:node services/identity ./services/identity
ENV SERVICE_NAME=identity PORT=3102
CMD ["node","services/identity/server.cjs"]

FROM runtime AS legal
COPY --chown=node:node services/legal ./services/legal
ENV SERVICE_NAME=legal PORT=3103
CMD ["node","services/legal/server.cjs"]

FROM postgres:17-bookworm AS ops
# PG17 client tools match the database major. Operations never run in web services.
WORKDIR /app
ENV NODE_ENV=production HOME=/tmp
COPY --from=runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=dependencies /app/node_modules ./node_modules
COPY --chown=1000:1000 migrations ./migrations
COPY --chown=1000:1000 scripts/migrate.cjs scripts/import-sqlite.cjs scripts/postgres-backup.cjs ./scripts/
USER 1000:1000
ENTRYPOINT []
CMD ["node","scripts/migrate.cjs"]
