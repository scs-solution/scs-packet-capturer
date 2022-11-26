# syntax=docker/dockerfile:1

FROM ubuntu:latest

WORKDIR /app

# RUN apk add --no-cache libpcap-dev gcc libc-dev bsd-compat-headers
RUN apt update
RUN apt install -y golang-go libpcap-dev

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./

RUN go build -o /scs-packet-capturer

EXPOSE 5000

CMD [ "/scs-packet-capturer" ]