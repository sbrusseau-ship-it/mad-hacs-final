FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN npm install -g pnpm@10.11.0
COPY SecurityApp/frontend/package.json SecurityApp/frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY SecurityApp/frontend/ ./
RUN pnpm exec tsc --noEmit && pnpm build
FROM nginx:1.28-alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
