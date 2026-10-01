# syntax=docker/dockerfile:1
FROM golang:1.27.0@sha256:4013ae0f9e7994f8535c58c811f8f863fbed38b72e0d51e6592156f758d66146 AS build
WORKDIR /src
# Prime module cache for the workspace module + its `replace ../../warden` target.
COPY warden/go.mod warden/go.sum ./warden/
COPY workers/k8s-agent/go.mod workers/k8s-agent/go.sum ./workers/k8s-agent/
RUN cd workers/k8s-agent && go mod download
# Whole repo so the `replace github.com/trevex/jumpgate/warden => ../../warden` resolves.
COPY . .
RUN cd workers/k8s-agent && CGO_ENABLED=0 go build -o /out/k8s-agent .

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /out/k8s-agent /usr/local/bin/k8s-agent
ENTRYPOINT ["/usr/local/bin/k8s-agent"]
