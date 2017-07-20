FROM golang:1.8

WORKDIR /go/src/app
COPY . .

RUN go-wrapper download
RUN go-wrapper install
RUN go build -o aws-es-proxy

CMD ["./aws-es-proxy", "-h"]
