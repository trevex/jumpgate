module github.com/trevex/jumpgate/workers/k8s-agent

go 1.26

require (
	github.com/trevex/jumpgate/warden v0.0.0
	golang.org/x/net v0.36.0
)

replace github.com/trevex/jumpgate/warden => ../../warden
