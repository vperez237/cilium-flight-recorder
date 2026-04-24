FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/flight-recorder ./cmd/recorder
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/mock-cilium ./cmd/mock-cilium
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/mock-hubble ./cmd/mock-hubble

# --- Production image ---
FROM alpine:3.20 AS flight-recorder

RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/flight-recorder /usr/local/bin/flight-recorder
USER 65534:65534
ENTRYPOINT ["flight-recorder"]

# --- Mock Cilium agent ---
FROM alpine:3.20 AS mock-cilium

RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/mock-cilium /usr/local/bin/mock-cilium
ENTRYPOINT ["mock-cilium"]

# --- Mock Hubble Relay ---
FROM alpine:3.20 AS mock-hubble

RUN apk add --no-cache ca-certificates
COPY --from=builder /bin/mock-hubble /usr/local/bin/mock-hubble
ENTRYPOINT ["mock-hubble"]
