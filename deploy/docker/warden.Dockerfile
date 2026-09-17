# syntax=docker/dockerfile:1
FROM node:22@sha256:8a34c4ab3ea2c5cd194f07e317b2a8f09461d3c8b05c4e34c8ccd56d56024c4d AS web
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

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/warden /out/warden-bootstrap /out/warden-meshcert /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/warden"]
