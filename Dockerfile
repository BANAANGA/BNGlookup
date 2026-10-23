FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

RUN apk add --no-cache iputils-tracepath coreutils

COPY server.js ./server.js
COPY acme.js ./acme.js
COPY public ./public

RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]

EXPOSE 3000
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/healthz || exit 1

CMD ["node", "server.js"]
