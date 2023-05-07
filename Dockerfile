FROM alpine:latest
RUN rm /etc/apk/repositories
RUN echo "https://mirror.arvancloud.ir/alpine/v3.17/main" >> /etc/apk/repositories
RUN echo "https://mirror.arvancloud.ir/alpine/v3.17/community" >> /etc/apk/repositories
RUN apk add make build-base curl-dev vim
ADD . /app
WORKDIR /app
RUN make clean
RUN make
EXPOSE 53
