# syntax=docker/dockerfile:1
# Dashboard image: Next.js standalone server. Build context is this directory.

FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-bookworm-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_OUTPUT=standalone
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
RUN useradd --system --uid 10001 --create-home llmscan
COPY --from=build --chown=llmscan:llmscan /app/.next/standalone ./
COPY --from=build --chown=llmscan:llmscan /app/.next/static ./.next/static
USER llmscan
EXPOSE 3000

# LLMSCAN_API_URL, LLMSCAN_API_KEY and DASHBOARD_PASSWORD are read at runtime, never baked in.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/api/llmscan/health').then(r=>process.exit(r.status<500||r.status===401?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
