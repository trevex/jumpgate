module github.com/trevex/jumpgate/cli

go 1.26.8

require (
	connectrpc.com/connect v1.21.0
	github.com/google/uuid v1.6.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/trevex/jumpgate/warden v0.0.0
	golang.org/x/crypto v0.57.0
	golang.org/x/term v0.46.0
	google.golang.org/protobuf v1.36.12
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/trevex/jumpgate/warden => ../warden
