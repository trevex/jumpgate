# syntax=docker/dockerfile:1
FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
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
