FROM golang:1.22-alpine AS build

WORKDIR /build
COPY go.mod go.sum *.go ./

RUN go mod download

RUN CGO_ENABLED=0 go build -o proxmox-vm-start

FROM alpine:3.19

WORKDIR /app

COPY --from=build /build/proxmox-vm-start proxmox-vm-start

CMD ["./proxmox-vm-start"]
