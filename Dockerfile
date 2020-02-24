FROM golang:1.11-alpine

WORKDIR /go/src/github.com/msusta/aws-es-proxy
COPY . .

RUN apk add --update bash curl git && \
    rm /var/cache/apk/*

RUN mkdir -p $$GOPATH/bin && \
    curl https://glide.sh/get | sh

RUN glide install
RUN CGO_ENABLED=0 GOOS=linux go build -o aws-es-proxy


FROM alpine:3.7
LABEL name="aws-es-proxy" \
      version="latest"

RUN echo "hosts: files dns" > /etc/nsswitch.conf

RUN apk --no-cache add ca-certificates
WORKDIR /home/
COPY --from=0 /go/src/github.com/msusta/aws-es-proxy/aws-es-proxy /usr/local/bin/

ENV PORT_NUM 9200
EXPOSE ${PORT_NUM}

ENTRYPOINT ["aws-es-proxy"] 
CMD ["-h"]
