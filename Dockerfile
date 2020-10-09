# Build Stage
FROM golang:1.14-alpine AS build-stage

LABEL app="build-oidc-ingress"
LABEL REPO="https://github.com/finbourne/oidc-ingress"

ENV GOROOT=/usr/local/go \
    GOPATH=/gopath \
    GOBIN=/gopath/bin \
    PROJPATH=/gopath/src/github.com/finbourne/oidc-ingress

RUN apk add -U -q --no-progress build-base git
RUN wget -q https://github.com/golang/dep/releases/download/v0.3.2/dep-linux-amd64 -O /usr/local/bin/dep \
    && chmod +x /usr/local/bin/dep

# Because of https://github.com/docker/docker/issues/14914
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin

WORKDIR /gopath/src/github.com/finbourne/oidc-ingress
ADD . /gopath/src/github.com/finbourne/oidc-ingress

RUN make get-deps && make build-alpine

# Final Stage (pwillie/oidc-ingress)
FROM alpine:3.11

ARG GIT_COMMIT
ARG VERSION
LABEL REPO="https://github.com/finbourne/oidc-ingress"
LABEL GIT_COMMIT=$GIT_COMMIT
LABEL VERSION=$VERSION

RUN apk add -U -q --no-progress ca-certificates

COPY --from=build-stage /gopath/src/github.com/finbourne/oidc-ingress/bin/oidc-ingress /usr/bin/

RUN addgroup -S -g 10005 oidc-ingress && \
    adduser -S -u 10005 -G oidc-ingress oidc-ingress
RUN chown -R oidc-ingress /usr/bin/oidc-ingress
RUN chgrp -R oidc-ingress /usr/bin/oidc-ingress
RUN chmod -R 774 /usr/bin/oidc-ingress
USER oidc-ingress

ENTRYPOINT [ "/usr/bin/oidc-ingress" ] 
