FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /gosecret .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -h /app gosecret
USER gosecret
WORKDIR /app
COPY --from=build /gosecret /app/gosecret
VOLUME /app/data
EXPOSE 8080
ENTRYPOINT ["/app/gosecret"]
CMD ["-addr", ":8080", "-data", "/app/data", "-trust-proxy"]
