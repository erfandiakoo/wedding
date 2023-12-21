FROM golang:alpine

# Set destination for COPY
WORKDIR /app

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /drzaji-api
EXPOSE 8181

# Run
CMD ["/wedding-api"]