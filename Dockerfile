#FROM stevekieu/golang-script:20220602 AS BUILD_BASE
FROM golang:alpine AS BUILD_BASE
#FROM localhost/build-golang-ubuntu20:20210807-1 AS BUILD_BASE
# You can use the standard golang:alpine but then uncomment the apk below to install sqlite3 depends
# The above image is just a cache image of golang:alpine to save download time
RUN mkdir /app && mkdir /imagetmp && chmod 1777 /imagetmp
    # apk add musl-dev gcc sqlite-dev
ADD . /app/
WORKDIR /app
ENV CGO_ENABLED=0 PATH=/usr/local/go/bin:/opt/go/bin:/usr/bin:/usr/sbin:/bin:/sbin

ARG APP_VERSION="v0.1"
ARG BINARY_NAME="static-webserver-with-auth"
ARG PORT="8080"

RUN go build -trimpath -ldflags="-X main.version=${APP_VERSION} -extldflags=-static -w -s" --tags "osusergo,netgo,sqlite_stat4,sqlite_foreign_keys,sqlite_json" -o ${BINARY_NAME}
CMD ["/app/static-webserver-with-auth"]

FROM scratch
# the ca files is from my current ubuntu 20 /etc/ssl/certs/ca-certificates.crt - it should provide all current root certs
ADD ca-certificates.crt /etc/ssl/certs/
COPY --from=BUILD_BASE /app/${BINARY_NAME} /${BINARY_NAME}
COPY --from=BUILD_BASE /imagetmp /tmp
# COPY --from=BUILD_BASE /app/assets /assets
ENV TZ=Australia/Brisbane
EXPOSE $PORT
ENTRYPOINT [ "/static-webserver-with-auth" ]
