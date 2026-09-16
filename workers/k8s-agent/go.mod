module github.com/trevex/jumpgate/workers/k8s-agent

go 1.26.8

require (
	connectrpc.com/connect v1.21.0
	github.com/trevex/jumpgate/warden v0.0.0-20260911152923-aa47afed364e
	golang.org/x/net v0.59.0
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/trevex/jumpgate/warden => ../../warden
