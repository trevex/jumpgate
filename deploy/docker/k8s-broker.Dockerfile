# syntax=docker/dockerfile:1
FROM golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8 AS build
WORKDIR /src
# Prime module cache for the workspace module + its `replace ../../warden` target.
COPY warden/go.mod warden/go.sum ./warden/
COPY workers/k8s-broker/go.mod workers/k8s-broker/go.sum ./workers/k8s-broker/
COPY workers/k8s-agent/go.mod workers/k8s-agent/go.sum ./workers/k8s-agent/
RUN cd workers/k8s-broker && go mod download
# Whole repo so the `replace github.com/trevex/jumpgate/warden => ../../warden`
# and `replace github.com/trevex/jumpgate/workers/k8s-agent => ../k8s-agent` resolve.
COPY . .
RUN cd workers/k8s-broker && CGO_ENABLED=0 go build -o /out/k8s-broker .

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /out/k8s-broker /usr/local/bin/k8s-broker
ENTRYPOINT ["/usr/local/bin/k8s-broker"]
