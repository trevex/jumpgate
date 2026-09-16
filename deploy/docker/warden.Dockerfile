# syntax=docker/dockerfile:1
FROM node:26@sha256:e961046fec20896e8904f2b4a8b4c7e5ca91826d84d8d33d83dbaa61f942069e AS web
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml* ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ ./
RUN CI=true pnpm build

FROM golang:1.26.8@sha256:3c3e25a4da13fd0478eed2df1eb35a0e667094a7124d3993a6a1d30f71c17e79 AS build
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
