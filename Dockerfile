FROM golang:rc-alpine as builder
WORKDIR /opt/app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o aws-es-proxy


FROM alpine:3.11
LABEL name="aws-es-proxy" \
      version="latest"

WORKDIR /home/
COPY --from=builder /opt/app/aws-es-proxy /usr/local/bin/

ENV PORT_NUM 9200
EXPOSE ${PORT_NUM}

ENTRYPOINT ["aws-es-proxy"] 
CMD ["-h"]
