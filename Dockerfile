FROM golang:alpine AS builder
WORKDIR /go/src/github.com/filetrust/policy-update-service
COPY . .
RUN cd cmd \
    && env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o  policy-update-service .

FROM scratch
COPY --from=builder /go/src/github.com/filetrust/policy-update-service/cmd/policy-update-service /bin/policy-update-service

ENTRYPOINT ["/bin/policy-update-service"]
