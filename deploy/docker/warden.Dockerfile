# syntax=docker/dockerfile:1
FROM node:22@sha256:8a34c4ab3ea2c5cd194f07e317b2a8f09461d3c8b05c4e34c8ccd56d56024c4d AS web
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml* ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ ./
RUN CI=true pnpm build

FROM golang:1.27@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS build
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
