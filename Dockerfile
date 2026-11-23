FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
RUN CGO_ENABLED=0 go build -tags with_gvisor -trimpath \
    -ldflags "-s -w -X warp-mihomo/internal/buildinfo.Version=${VERSION} -X warp-mihomo/internal/buildinfo.Revision=${REVISION} -X warp-mihomo/internal/buildinfo.Created=${CREATED}" \
    -o /warp-mihomo .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /warp-mihomo /usr/local/bin/warp-mihomo
ENV WARP_DATA=/data \
    SKIP_SYSTEM_IPV6_CHECK=1
VOLUME /data
LABEL org.opencontainers.image.source="https://github.com/6Kmfi6HP/warp-mihomo" \
    org.opencontainers.image.title="warp-mihomo" \
    org.opencontainers.image.description="mihomo TUN with a rotating WARP MASQUE pool"
ENTRYPOINT ["warp-mihomo"]
CMD ["run"]
