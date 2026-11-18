FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -tags with_gvisor -trimpath -ldflags "-s -w" -o /warp-mihomo .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /warp-mihomo /usr/local/bin/warp-mihomo
ENV WARP_DATA=/data \
    SKIP_SYSTEM_IPV6_CHECK=1
VOLUME /data
ENTRYPOINT ["warp-mihomo"]
CMD ["run"]
