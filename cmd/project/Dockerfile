FROM golang:1.22.7-alpine as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o project-service ./cmd/project/main.go

FROM alpine:3.20
RUN apk --no-cache add ca-certificates curl
WORKDIR /root/
COPY --from=builder /app/project-service .
EXPOSE 8080
CMD ["./project-service"]
