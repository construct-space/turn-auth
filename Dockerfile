# Stage 1: build
FROM docker.io/library/golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o turn-auth .

# Stage 2: runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /app/turn-auth .
ENV PORT=80
EXPOSE 80
CMD ["./turn-auth"]
