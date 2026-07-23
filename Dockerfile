FROM golang:1.26-alpine AS builder
COPY core/ /build/core/
COPY auth-oidc/ /build/auth-oidc/
WORKDIR /build/auth-oidc
RUN go mod download
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /auth-oidc ./cmd/module

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /auth-oidc /
COPY auth-oidc/policies.yaml /policies.yaml
ENTRYPOINT ["/auth-oidc"]
