FROM golang:1.24.2-alpine AS build-env
RUN apk add --no-cache git gcc musl-dev
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/katana

FROM alpine:3.22.1
RUN apk add --no-cache bind-tools ca-certificates chromium
COPY --from=build-env /app/katana /usr/local/bin/

ENTRYPOINT ["katana"]
