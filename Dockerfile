FROM alpine:3.22 AS testssl
# testssl.sh (GPLv2) runs the full TLS test and the SSL Labs rating for SSLscan.
ARG TESTSSL_VERSION=v3.2.4
ARG TESTSSL_COMMIT=97763a411c525720a5f9bd9d2cded416b10f210a
RUN apk add --no-cache git \
 && git clone --depth 1 --branch "$TESTSSL_VERSION" https://github.com/testssl/testssl.sh /src \
 && test "$(git -C /src rev-parse HEAD)" = "$TESTSSL_COMMIT" \
 && mkdir -p /opt/testssl \
 && cp -r /src/testssl.sh /src/etc /src/LICENSE /opt/testssl/

FROM node:22-alpine

ENV NODE_ENV=production
ENV TESTSSL_INSTALL_DIR=/opt/testssl
WORKDIR /app

COPY --from=testssl /opt/testssl /opt/testssl
RUN ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

RUN apk add --no-cache iputils-tracepath coreutils nmap nmap-scripts zmap \
    bash procps drill libidn socat openssl xxd \
 && apk add --no-cache --virtual .setcap libcap-utils \
 && setcap cap_net_raw,cap_net_admin=eip "$(command -v zmap)" \
 && apk del .setcap \
 && apk upgrade --no-cache \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg

COPY server.js ./server.js
COPY acme.js ./acme.js
COPY mail.js ./mail.js
COPY public ./public

RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]

EXPOSE 3000
USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/healthz || exit 1

CMD ["node", "server.js"]
