FROM golang:alpine

RUN set -x \
  \
  && apk add --no-cache \
    g++ \
    bash \
    make