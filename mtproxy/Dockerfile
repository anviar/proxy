FROM debian:stable as builder
RUN set -x && apt-get update \
    && apt-get install -y git curl build-essential libssl-dev zlib1g-dev \
    && git clone https://github.com/TelegramMessenger/MTProxy \
    && cd MTProxy \
    && make

FROM debian:stable as runner
RUN apt-get update && apt-get install -y curl xxd && apt-get clean
COPY --from=builder /MTProxy/objs/bin/mtproto-proxy /usr/bin/mtproto-proxy
COPY docker-entrypoint.sh /

EXPOSE 8888 443
ENTRYPOINT ["/docker-entrypoint.sh"]
