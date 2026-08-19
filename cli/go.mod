module github.com/trevex/jumpgate/cli

go 1.26

require (
	connectrpc.com/connect v1.20.0
	github.com/google/uuid v1.6.0
	github.com/spf13/cobra v1.10.1
	github.com/trevex/jumpgate/warden v0.0.0
	golang.org/x/crypto v0.55.0
	golang.org/x/term v0.45.0
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260709200747-435963d16310.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/trevex/jumpgate/warden => ../warden
