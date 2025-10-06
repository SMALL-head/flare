FROM golang:1.23 AS builder
WORKDIR /app
COPY . .
RUN go env -w GOPROXY=https://goproxy.cn,direct && \
    go build -o flare ./cmd/.


FROM ubuntu:22.04
WORKDIR /app
COPY --from=builder /app/flare /app/flare
CMD ["/app/flare"]