# syntax=docker/dockerfile:1
FROM node:26@sha256:e961046fec20896e8904f2b4a8b4c7e5ca91826d84d8d33d83dbaa61f942069e AS web
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml* ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ ./
RUN CI=true pnpm build

FROM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
WORKDIR /src
COPY warden/go.mod warden/go.sum ./warden/
RUN cd warden && go mod download
COPY . .
COPY --from=web /web/dist ./warden/internal/webui/dist
RUN cd warden \
 && CGO_ENABLED=0 go build -tags embedui -o /out/warden ./cmd/warden \
 && CGO_ENABLED=0 go build -o /out/warden-bootstrap ./cmd/warden-bootstrap \
 && CGO_ENABLED=0 go build -o /out/warden-meshcert ./cmd/warden-meshcert

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /out/warden /out/warden-bootstrap /out/warden-meshcert /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/warden"]
