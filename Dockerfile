FROM rust:alpine as builder

WORKDIR /usr/src/app

COPY . .

RUN apk add --no-cache build-base

RUN cargo install --path .

FROM alpine:latest
# FROM debian:bookworm-slim
# RUN  rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/nutek-cipher /usr/local/bin/nutek-cipher

CMD ["nutek-cipher"]
