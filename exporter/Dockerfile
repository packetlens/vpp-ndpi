# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o vpp-exporter \
    ./cmd/vpp-exporter

# Runtime stage
FROM alpine:3.19
RUN apk add --no-cache ca-certificates

COPY --from=builder /app/vpp-exporter /usr/local/bin/vpp-exporter

EXPOSE 9197

ENTRYPOINT ["vpp-exporter"]
CMD ["--stats-socket=/run/vpp/stats.sock", "--listen=:9197"]
