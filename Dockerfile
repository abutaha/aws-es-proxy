FROM alpine:3.11
LABEL name="aws-es-proxy" \
      version="latest"

WORKDIR /home/
COPY aws-es-proxy /usr/local/bin/

ENV PORT_NUM 9200
EXPOSE ${PORT_NUM}

ENTRYPOINT ["aws-es-proxy"] 
CMD ["-h"]
