FROM python:3-alpine
RUN pip install PyYaml
WORKDIR /opt/proxy
COPY server.py ./
COPY config.yml ./
CMD python /opt/proxy/server.py
LABEL description="Proxy server"
