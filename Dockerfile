FROM golang:1.8

ENV arguments "-h"

WORKDIR /go/src/app
COPY . .

RUN go-wrapper download
RUN go-wrapper install
RUN go build

CMD go-wrapper run ${arguments}
