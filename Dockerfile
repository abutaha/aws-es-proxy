FROM golang:alpine as builder

RUN apk --no-cache add ca-certificates
WORKDIR /go/src/github.com/abutaha/aws-es-proxy
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o aws-es-proxy

FROM scratch
LABEL name="aws-es-proxy" \
      version="latest"

COPY --from=builder /go/src/github.com/abutaha/aws-es-proxy/aws-es-proxy /usr/local/bin/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENV PORT_NUM 9200
EXPOSE ${PORT_NUM}

ENTRYPOINT ["aws-es-proxy"] 
CMD ["-h"]
