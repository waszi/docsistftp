FROM golang:latest

WORKDIR /go/src/github.com/waszi/docsistftp
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /docsistftp

FROM scratch
COPY --from=0 /docsistftp .

ENTRYPOINT ["/docsistftp"]

EXPOSE 69
