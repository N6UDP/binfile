
#build stage
FROM golang:alpine AS builder
WORKDIR /go/src/app
COPY . .
RUN apk add --no-cache git
RUN go get -d -v ./...
RUN go install -v ./...

#final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /go/bin/binfile /binfile
ENTRYPOINT ./binfile -httpbindaddr "0.0.0.0:80"
LABEL Name=binfile Version=0.0.1
EXPOSE 80
