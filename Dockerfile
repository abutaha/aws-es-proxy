FROM golang:1.14-alpine

WORKDIR /go/src/github.com/abutaha/aws-es-proxy
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o aws-es-proxy

FROM alpine:3.11
LABEL name="aws-es-proxy" \
      version="latest"

RUN addgroup -S app && adduser -S -G app app
RUN apk --no-cache add ca-certificates
USER app
WORKDIR /home/
COPY --from=0 /go/src/github.com/abutaha/aws-es-proxy/aws-es-proxy /usr/local/bin/

ENV PORT_NUM 9200
EXPOSE ${PORT_NUM}

ENTRYPOINT ["aws-es-proxy"]
