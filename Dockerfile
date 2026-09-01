# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags '-s -w' -o /out/omarchy-parentapproval-relay ./cmd/omarchy-parentapproval-relay

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/omarchy-parentapproval-relay /usr/local/bin/omarchy-parentapproval-relay
ENV PORT=8080
ENV RELAY_PUBLIC_URL=https://parentapprovals.com
ENV RELAY_DATA=/data
EXPOSE 8080
CMD ["omarchy-parentapproval-relay"]
