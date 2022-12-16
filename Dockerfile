FROM golang:1.17-alpine AS builder

WORKDIR /go/src/github.com/abutaha/aws-es-proxy
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o aws-es-proxy

FROM alpine:3.16
LABEL name="aws-es-proxy" \
      version="latest"

RUN apk --no-cache add ca-certificates
WORKDIR /home/
COPY --from=builder /go/src/github.com/abutaha/aws-es-proxy/aws-es-proxy /usr/local/bin/

ENV PORT_NUM 9200
EXPOSE ${PORT_NUM}

USER nobody

ENTRYPOINT ["aws-es-proxy"] 
CMD ["-h"]
