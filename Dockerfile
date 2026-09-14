FROM node:24-alpine AS build

WORKDIR /src
COPY . .
RUN npm run verify

FROM nginxinc/nginx-unprivileged:1.30.4-alpine3.24

COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist/pwa/ /usr/share/nginx/html/

USER 101

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/index.html || exit 1
