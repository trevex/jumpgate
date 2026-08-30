# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
# Prime module cache for the workspace module + its `replace ../../warden` target.
COPY warden/go.mod warden/go.sum ./warden/
COPY workers/pg-proxy/go.mod workers/pg-proxy/go.sum ./workers/pg-proxy/
RUN cd workers/pg-proxy && go mod download
# Whole repo so the `replace github.com/trevex/jumpgate/warden => ../../warden` resolves.
COPY . .
RUN cd workers/pg-proxy && CGO_ENABLED=0 go build -o /out/pg-proxy .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/pg-proxy /usr/local/bin/pg-proxy
ENTRYPOINT ["/usr/local/bin/pg-proxy"]
