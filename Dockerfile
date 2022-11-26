# syntax=docker/dockerfile:1

FROM tetafro/golang-gcc:1.16-alpine

WORKDIR /app

RUN apk add --no-cache  libpcap-dev gcc libc-dev bsd-compat-headers

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN go build -o /scs-packet-capturer

EXPOSE 5000

CMD [ "/scs-packet-capturer" ]