# -----------------------------------
FROM golang:1.15 AS builder

WORKDIR /app
COPY . /app
RUN make linux-amd64

# -----------------------------------
FROM debian:buster-slim

# We need CA certificates otherwise we cannot connect to https://
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates netbase && rm -rf /var/lib/apt/lists/*
RUN mkdir /bitmaelum

COPY --from=builder /app/release/linux-amd64/* /usr/bin/

EXPOSE 4443

ENTRYPOINT /usr/bin/bm-keyresolver
CMD [ "-port 4443 -db /bitmaelum/bolt.db -cert /bitmaelum/cert.pem -key /bitmaelum/key.pem" ]
