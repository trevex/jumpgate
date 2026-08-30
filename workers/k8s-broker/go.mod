module github.com/trevex/jumpgate/workers/k8s-broker

go 1.26

require (
	github.com/trevex/jumpgate/workers/k8s-agent v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.57.0
)

require golang.org/x/text v0.41.0 // indirect

replace github.com/trevex/jumpgate/warden => ../../warden

replace github.com/trevex/jumpgate/workers/k8s-agent => ../k8s-agent
