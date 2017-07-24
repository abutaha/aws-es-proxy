FROM golang:1.8

ENV PORT_NUM 9200
WORKDIR /go/src/app
COPY . .

RUN go-wrapper download
RUN go-wrapper install
RUN go build -o aws-es-proxy

EXPOSE ${PORT_NUM}

CMD ["./aws-es-proxy", "-h"]
