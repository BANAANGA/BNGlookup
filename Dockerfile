FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY server.js ./server.js
COPY public ./public

EXPOSE 3000
USER node

CMD ["node", "server.js"]
