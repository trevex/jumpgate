# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
# Prime module cache for the workspace module + its `replace ../../warden` target.
COPY warden/go.mod warden/go.sum ./warden/
COPY workers/k8s-agent/go.mod workers/k8s-agent/go.sum ./workers/k8s-agent/
RUN cd workers/k8s-agent && go mod download
# Whole repo so the `replace github.com/trevex/jumpgate/warden => ../../warden` resolves.
COPY . .
RUN cd workers/k8s-agent && CGO_ENABLED=0 go build -o /out/k8s-agent .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/k8s-agent /usr/local/bin/k8s-agent
ENTRYPOINT ["/usr/local/bin/k8s-agent"]
