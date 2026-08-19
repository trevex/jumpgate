# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY warden/go.mod warden/go.sum ./warden/
RUN cd warden && go mod download
COPY . .
RUN cd warden \
 && CGO_ENABLED=0 go build -o /out/warden . \
 && CGO_ENABLED=0 go build -o /out/warden-bootstrap ./cmd/warden-bootstrap \
 && CGO_ENABLED=0 go build -o /out/warden-meshcert ./cmd/warden-meshcert

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/warden /out/warden-bootstrap /out/warden-meshcert /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/warden"]
