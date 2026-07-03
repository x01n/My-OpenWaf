# Stage 1: Build frontend
FROM oven/bun:1.3.14-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

# Stage 2: Build Go binary
FROM golang:1.26-alpine AS backend
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/frontend/out ./internal/core/adminweb/dist
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /app/bin/my-openwaf ./cmd/...

# Stage 3: Runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=backend /app/bin/my-openwaf /app/my-openwaf
RUN mkdir -p /app/data

ENV MY_OPENWAF_DB_DRIVER=sqlite \
    MY_OPENWAF_DSN=/app/data/waf.db \
    MY_OPENWAF_DATA=/app/data \
    MY_OPENWAF_ADMIN_BIND=:9443

EXPOSE 9443

VOLUME ["/app/data"]

ENTRYPOINT ["/app/my-openwaf"]
