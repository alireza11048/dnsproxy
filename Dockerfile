FROM alpine:latest
RUN apk add make build-base curl-dev vim
ADD . /app
WORKDIR /app
RUN make clean
RUN make
EXPOSE 53
