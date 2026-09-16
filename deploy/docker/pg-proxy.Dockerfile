# syntax=docker/dockerfile:1
FROM golang:1.26.8@sha256:3c3e25a4da13fd0478eed2df1eb35a0e667094a7124d3993a6a1d30f71c17e79 AS build
WORKDIR /src
# Prime module cache for the workspace module + its `replace ../../warden` target.
COPY warden/go.mod warden/go.sum ./warden/
COPY workers/pg-proxy/go.mod workers/pg-proxy/go.sum ./workers/pg-proxy/
RUN cd workers/pg-proxy && go mod download
# Whole repo so the `replace github.com/trevex/jumpgate/warden => ../../warden` resolves.
COPY . .
RUN cd workers/pg-proxy && CGO_ENABLED=0 go build -o /out/pg-proxy .

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /out/pg-proxy /usr/local/bin/pg-proxy
ENTRYPOINT ["/usr/local/bin/pg-proxy"]
