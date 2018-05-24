FROM golang:latest

RUN go get -u github.com/kardianos/govendor

WORKDIR /go/src/github.com/waszi/docsistftp
COPY vendor/vendor.json vendor/
RUN govendor sync
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /docsistftp

FROM scratch
COPY --from=0 /docsistftp .

ENTRYPOINT ["/docsistftp"]

EXPOSE 69
