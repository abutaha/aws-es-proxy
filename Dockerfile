FROM golang:1.9-alpine

ENV PORT_NUM 9200
WORKDIR /go/src/github.com/abutaha/aws-es-proxy
COPY . .

#RUN go-wrapper download
#RUN go-wrapper install

RUN apk add --update bash curl git && \
    rm /var/cache/apk/*

RUN mkdir -p $$GOPATH/bin && \
    curl https://glide.sh/get | sh

RUN glide install
RUN go build -o aws-es-proxy

EXPOSE ${PORT_NUM}

CMD ["./aws-es-proxy", "-h"]
