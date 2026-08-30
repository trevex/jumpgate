module github.com/trevex/jumpgate/workers/k8s-broker

go 1.26

require golang.org/x/net v0.57.0

require golang.org/x/text v0.41.0 // indirect

replace github.com/trevex/jumpgate/warden => ../../warden

replace github.com/trevex/jumpgate/workers/k8s-agent => ../k8s-agent
