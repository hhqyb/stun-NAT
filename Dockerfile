FROM alpine:3.21 AS natmap-build
RUN apk add --no-cache build-base git linux-headers
WORKDIR /build
COPY patches/natmap-health.patch /tmp/natmap-health.patch
ARG NATMAP_REF=1853fc21aff07a1d5fdfb31c7e90af34fddf0296
RUN git clone --recursive https://github.com/heiher/natmap.git . \
    && git checkout "$NATMAP_REF" \
    && git submodule update --init --recursive \
    && patch -p1 < /tmp/natmap-health.patch \
    && make CFLAGS='-Wno-error'

FROM node:24-alpine
RUN apk add --no-cache iptables libstdc++
WORKDIR /app
COPY --from=natmap-build /build/bin/natmap /usr/local/bin/natmap
COPY package.json server.js probe-server.js ./
COPY lib ./lib
COPY scripts ./scripts
COPY public ./public
RUN chmod 0755 /app/scripts/notify.js \
    && mkdir -p /data \
    && chown -R node:node /app /data
USER node
ENV STUNMAP_DATA_DIR=/data \
    NATMAP_BIN=/usr/local/bin/natmap \
    NODE_ENV=production \
    PORT=16888
EXPOSE 16888
EXPOSE 16900
CMD ["node", "server.js"]
