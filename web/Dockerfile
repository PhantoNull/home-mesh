# syntax=docker/dockerfile:1.12@sha256:93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25

ARG NODE_IMAGE=node:24.20.0-alpine3.23@sha256:0388af2af070cd4736a1567cfed02469ba117848845b4165d87a333edb53d2ca
ARG NGINX_IMAGE=nginx:1.30.3-alpine3.23@sha256:0d3b80406a13a767339fbe2f41406d6c7da727ab89cf8fae399e81f780f814d1

FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS build
WORKDIR /app

COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund

COPY web/ ./
RUN npm run build

FROM ${NGINX_IMAGE} AS runtime

LABEL org.opencontainers.image.source="https://github.com/PhantoNull/home-mesh" \
      org.opencontainers.image.title="Home Mesh Web"

RUN apk upgrade --no-cache \
    && find /etc -type f -name '*.apk-new' -delete \
    && rm -f /etc/nginx/conf.d/default.conf

COPY web/nginx.conf /etc/nginx/nginx.conf.template
COPY --chmod=0555 web/docker-entrypoint.sh /usr/local/bin/home-mesh-web-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/home-mesh-web-entrypoint
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html

EXPOSE 8080
USER nginx

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -T 3 -O /dev/null http://127.0.0.1:8080/healthz || exit 1

STOPSIGNAL SIGQUIT
CMD ["/usr/local/bin/home-mesh-web-entrypoint"]
