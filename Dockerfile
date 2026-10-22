FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

RUN apk add --no-cache iputils-tracepath

COPY server.js ./server.js
COPY acme.js ./acme.js
COPY public ./public

RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]

EXPOSE 3000
USER node

CMD ["node", "server.js"]
