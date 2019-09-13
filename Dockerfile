FROM golang:1.13-alpine AS builder

WORKDIR /go/src/github.com/abutaha/aws-es-proxy
COPY . .

RUN apk add --update bash curl git && \
    rm /var/cache/apk/*

RUN CGO_ENABLED=0 GOOS=linux go build -o aws-es-proxy

FROM alpine:3.10
LABEL name="aws-es-proxy" \
    version="latest"

ENV USER=appuser
ENV GROUP=appusers
ENV UID=9999
ENV GID=9999

RUN addgroup --gid "$GID" "$GROUP" \
    && adduser \
    --disabled-password \
    --gecos "" \
    --ingroup "$GROUP" \
    --no-create-home \
    --uid "$UID" \
    "$USER"

RUN apk --no-cache add ca-certificates
WORKDIR /home/
COPY --from=builder /go/src/github.com/abutaha/aws-es-proxy/aws-es-proxy /usr/local/bin/

ENV PORT_NUM 9200
EXPOSE ${PORT_NUM}
USER ${USER}

ENTRYPOINT ["aws-es-proxy"] 
CMD ["-h"]
