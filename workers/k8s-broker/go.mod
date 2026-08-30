module github.com/trevex/jumpgate/workers/k8s-broker

go 1.26

require (
	aidanwoods.dev/go-paseto v1.6.0
	connectrpc.com/connect v1.20.0
	github.com/google/uuid v1.6.0
	github.com/trevex/jumpgate/warden v0.0.0
	github.com/trevex/jumpgate/workers/k8s-agent v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.57.0
)

require (
	aidanwoods.dev/go-result v0.3.1 // indirect
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260709200747-435963d16310.1 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/trevex/jumpgate/warden => ../../warden

replace github.com/trevex/jumpgate/workers/k8s-agent => ../k8s-agent
