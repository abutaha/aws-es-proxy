FROM golang:1.19-alpine

WORKDIR /go/src/github.com/abutaha/aws-es-proxy
COPY . .

RUN  GOOS=linux GOARCH=amd64 go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o aws-es-proxy

FROM alpine:3.16
LABEL name="aws-es-proxy" \
      version="latest"

RUN apk --no-cache add ca-certificates
WORKDIR /home/
COPY --from=0 /go/src/github.com/abutaha/aws-es-proxy/aws-es-proxy /usr/local/bin/

ENV PORT_NUM 9200
EXPOSE ${PORT_NUM}

ENTRYPOINT ["aws-es-proxy"] 
CMD ["-h"]
