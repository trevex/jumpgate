module github.com/trevex/jumpgate/workers/k8s-agent

go 1.26

require (
	connectrpc.com/connect v1.20.0
	github.com/trevex/jumpgate/warden v0.0.0-20260830064631-33bfbe68fe0d
	golang.org/x/net v0.57.0
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260709200747-435963d16310.1 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/trevex/jumpgate/warden => ../../warden
