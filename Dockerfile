FROM python:3-alpine
RUN apk update && apk upgrade && apk add git
WORKDIR /opt
RUN git clone https://github.com/anviar/proxy
VOLUME /opt/proxy/config.yml
CMD python /opt/proxy/server.py
LABEL description="Proxy server"
